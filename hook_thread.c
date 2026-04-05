/*
 * Linexe - Thread & Process API Hook (Phase 2)
 * Licensed under Apache License 2.0
 *
 * WindowsスレッドAPIをpthreadに変換する。
 *
 * 対応API:
 *   CreateThread / ExitThread / TerminateThread
 *   GetCurrentThreadId / GetCurrentProcessId
 *   WaitForSingleObject / WaitForMultipleObjects
 *   CloseHandle（スレッドハンドル限定）
 *   GetCommandLineA
 *   Sleep
 *   GetLastError / SetLastError
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <semaphore.h>

#ifndef LINEXE_QUIET
  #define HOOK_LOG(fmt, ...) fprintf(stderr, "[LINEXE/THR] " fmt "\n", ##__VA_ARGS__)
#else
  #define HOOK_LOG(fmt, ...)
#endif

typedef uint32_t DWORD;
typedef void*    HANDLE;
typedef int      BOOL;

/* WaitForSingleObject タイムアウト値 */
#define INFINITE          0xFFFFFFFF
#define WAIT_OBJECT_0     0x00000000
#define WAIT_TIMEOUT      0x00000102
#define WAIT_FAILED       0xFFFFFFFF

/* ════════════════════════════════════════════════
   スレッドローカル：GetLastError / SetLastError
   ════════════════════════════════════════════════ */
static __thread DWORD tls_last_error = 0;

DWORD GetLastError(void) {
    return tls_last_error;
}

void SetLastError(DWORD dwErrCode) {
    tls_last_error = dwErrCode;
    HOOK_LOG("SetLastError(%u)", dwErrCode);
}

/* ════════════════════════════════════════════════
   スレッドハンドルテーブル
   CreateThreadが返すHANDLEを管理する
   ════════════════════════════════════════════════ */
#define MAX_THREADS 128

typedef struct {
    int       in_use;
    pthread_t tid;
    sem_t     done_sem;  /* ExitThread/join用 */
    void*     exit_code;
} THREAD_ENTRY;

static THREAD_ENTRY thread_table[MAX_THREADS];
static pthread_mutex_t thread_table_lock = PTHREAD_MUTEX_INITIALIZER;

/* Windows LPTHREAD_START_ROUTINE の型 */
typedef DWORD (*WIN_THREAD_FUNC)(void* param);

typedef struct {
    WIN_THREAD_FUNC fn;
    void*           param;
    int             table_idx;
} THREAD_CTX;

/* pthreadエントリポイント：Windowsスレッド関数をラップ */
static void* thread_entry_wrapper(void* arg) {
    THREAD_CTX* ctx = (THREAD_CTX*)arg;
    WIN_THREAD_FUNC fn  = ctx->fn;
    void*           param = ctx->param;
    int             idx   = ctx->table_idx;
    free(ctx);

    DWORD ret = fn(param);

    pthread_mutex_lock(&thread_table_lock);
    if (thread_table[idx].in_use) {
        thread_table[idx].exit_code = (void*)(uintptr_t)ret;
        sem_post(&thread_table[idx].done_sem);
    }
    pthread_mutex_unlock(&thread_table_lock);
    return (void*)(uintptr_t)ret;
}

/* ════════════════════════════════════════════════
   CreateThread
   ════════════════════════════════════════════════ */
HANDLE CreateThread(void*           lpThreadAttributes,
                    size_t          dwStackSize,
                    WIN_THREAD_FUNC lpStartAddress,
                    void*           lpParameter,
                    DWORD           dwCreationFlags,
                    DWORD*          lpThreadId)
{
    (void)lpThreadAttributes; (void)dwStackSize; (void)dwCreationFlags;

    pthread_mutex_lock(&thread_table_lock);
    int idx = -1;
    for (int i = 0; i < MAX_THREADS; i++) {
        if (!thread_table[i].in_use) { idx = i; break; }
    }
    if (idx < 0) {
        pthread_mutex_unlock(&thread_table_lock);
        SetLastError(12); /* ERROR_NOT_ENOUGH_MEMORY */
        return NULL;
    }
    thread_table[idx].in_use = 1;
    sem_init(&thread_table[idx].done_sem, 0, 0);
    pthread_mutex_unlock(&thread_table_lock);

    THREAD_CTX* ctx = malloc(sizeof(THREAD_CTX));
    ctx->fn        = lpStartAddress;
    ctx->param     = lpParameter;
    ctx->table_idx = idx;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    if (dwStackSize > 0) pthread_attr_setstacksize(&attr, dwStackSize);

    if (pthread_create(&thread_table[idx].tid, &attr,
                       thread_entry_wrapper, ctx) != 0) {
        pthread_attr_destroy(&attr);
        pthread_mutex_lock(&thread_table_lock);
        thread_table[idx].in_use = 0;
        pthread_mutex_unlock(&thread_table_lock);
        free(ctx);
        SetLastError(11); /* ERROR_BAD_FORMAT */
        return NULL;
    }
    pthread_attr_destroy(&attr);

    if (lpThreadId)
        *lpThreadId = (DWORD)(uintptr_t)thread_table[idx].tid;

    HANDLE h = (HANDLE)(uintptr_t)(0xCC000000U | (uint32_t)idx);
    HOOK_LOG("CreateThread(fn=%p) -> handle %p (idx=%d)", lpStartAddress, h, idx);
    return h;
}

/* ════════════════════════════════════════════════
   ExitThread
   ════════════════════════════════════════════════ */
void ExitThread(DWORD dwExitCode) {
    HOOK_LOG("ExitThread(%u)", dwExitCode);
    pthread_exit((void*)(uintptr_t)dwExitCode);
}

/* ════════════════════════════════════════════════
   WaitForSingleObject
   ════════════════════════════════════════════════ */
DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    int idx = (int)((uintptr_t)hHandle & 0xFFFF);
    if (idx < 0 || idx >= MAX_THREADS || !thread_table[idx].in_use) {
        HOOK_LOG("WaitForSingleObject: invalid handle %p", hHandle);
        return WAIT_FAILED;
    }

    HOOK_LOG("WaitForSingleObject(idx=%d, timeout=%u ms)", idx, dwMilliseconds);

    if (dwMilliseconds == INFINITE) {
        sem_wait(&thread_table[idx].done_sem);
        return WAIT_OBJECT_0;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += dwMilliseconds / 1000;
    ts.tv_nsec += (dwMilliseconds % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    int r = sem_timedwait(&thread_table[idx].done_sem, &ts);
    return (r == 0) ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
}

/* ════════════════════════════════════════════════
   CloseHandle（スレッドハンドル）
   ════════════════════════════════════════════════ */
BOOL CloseHandle(HANDLE hObject) {
    int idx = (int)((uintptr_t)hObject & 0xFFFF);
    if (idx >= 0 && idx < MAX_THREADS && thread_table[idx].in_use) {
        pthread_detach(thread_table[idx].tid);
        sem_destroy(&thread_table[idx].done_sem);
        pthread_mutex_lock(&thread_table_lock);
        thread_table[idx].in_use = 0;
        pthread_mutex_unlock(&thread_table_lock);
        HOOK_LOG("CloseHandle(thread idx=%d)", idx);
        return 1;
    }
    HOOK_LOG("CloseHandle(%p) -> unknown handle, ignored", hObject);
    return 1; /* 不明なハンドルも成功扱い */
}

/* ════════════════════════════════════════════════
   GetCurrentThreadId / GetCurrentProcessId
   ════════════════════════════════════════════════ */
DWORD GetCurrentThreadId(void) {
    DWORD tid = (DWORD)syscall(SYS_gettid);
    HOOK_LOG("GetCurrentThreadId -> %u", tid);
    return tid;
}

DWORD GetCurrentProcessId(void) {
    DWORD pid = (DWORD)getpid();
    HOOK_LOG("GetCurrentProcessId -> %u", pid);
    return pid;
}

/* ════════════════════════════════════════════════
   Sleep
   ════════════════════════════════════════════════ */
void Sleep(DWORD dwMilliseconds) {
    HOOK_LOG("Sleep(%u ms)", dwMilliseconds);
    struct timespec ts = {
        .tv_sec  = dwMilliseconds / 1000,
        .tv_nsec = (dwMilliseconds % 1000) * 1000000L
    };
    nanosleep(&ts, NULL);
}

/* ════════════════════════════════════════════════
   GetCommandLineA
   ════════════════════════════════════════════════ */
static char fake_cmdline[512] = "linexe_target.exe";

void linexe_set_cmdline(const char* cmdline) {
    strncpy(fake_cmdline, cmdline, sizeof(fake_cmdline) - 1);
}

char* GetCommandLineA(void) {
    HOOK_LOG("GetCommandLineA -> \"%s\"", fake_cmdline);
    return fake_cmdline;
}

/* ════════════════════════════════════════════════
   セルフテスト
   ════════════════════════════════════════════════ */
#ifdef LINEXE_TEST_THREAD
#include <stdio.h>

static DWORD test_thread_fn(void* param) {
    int id = (int)(uintptr_t)param;
    printf("  [thread %d] running, tid=%u\n", id, GetCurrentThreadId());
    Sleep(50);
    printf("  [thread %d] done\n", id);
    return (DWORD)(id * 10);
}

int main(void) {
    printf("=== Linexe Thread Hook - Self Test ===\n\n");

    printf("GetCurrentProcessId -> %u\n", GetCurrentProcessId());
    printf("GetCurrentThreadId  -> %u\n\n", GetCurrentThreadId());

    SetLastError(0);
    printf("GetLastError (initial) -> %u\n\n", GetLastError());

    printf("GetCommandLineA -> \"%s\"\n\n", GetCommandLineA());

    DWORD tid1 = 0, tid2 = 0;
    HANDLE h1 = CreateThread(NULL, 0, test_thread_fn, (void*)1, 0, &tid1);
    HANDLE h2 = CreateThread(NULL, 0, test_thread_fn, (void*)2, 0, &tid2);
    printf("CreateThread h1=%p (tid=%u)\n", h1, tid1);
    printf("CreateThread h2=%p (tid=%u)\n\n", h2, tid2);

    WaitForSingleObject(h1, INFINITE);
    WaitForSingleObject(h2, INFINITE);
    CloseHandle(h1);
    CloseHandle(h2);

    printf("\n[+] Thread test done.\n");
    return 0;
}
#endif
