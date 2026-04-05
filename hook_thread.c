/*
 * Linexe - Thread / Process Hook Layer (patched draft)
 * Minimal safety pass: lock around thread table access, safer handle checks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

typedef uint32_t DWORD;
typedef int BOOL;
typedef void* HANDLE;
typedef void* LPVOID;
typedef DWORD (*LPTHREAD_START_ROUTINE)(LPVOID);

typedef struct {
    pthread_t thread;
    sem_t done_sem;
    int in_use;
} ThreadSlot;

#define TRUE 1
#define FALSE 0
#define INFINITE 0xFFFFFFFFu
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 258
#define WAIT_FAILED 0xFFFFFFFFu
#define ERROR_INVALID_HANDLE 6
#define ERROR_NOT_ENOUGH_MEMORY 8
#define MAX_THREADS 256

static __thread DWORD tls_last_error = 0;
static ThreadSlot thread_table[MAX_THREADS];
static pthread_mutex_t g_thread_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    LPTHREAD_START_ROUTINE start;
    LPVOID param;
    int slot_index;
} ThreadStartCtx;

static int handle_to_index(HANDLE h) {
    uintptr_t v = (uintptr_t)h;
    if ((v & 0xFF000000u) != 0xCC000000u) return -1;
    return (int)(v & 0x00FFFFFFu);
}

static HANDLE index_to_handle(int idx) {
    return (HANDLE)(uintptr_t)(0xCC000000u | (uint32_t)idx);
}

static void *thread_start_trampoline(void *arg) {
    ThreadStartCtx *ctx = (ThreadStartCtx *)arg;
    DWORD ret = 0;
    if (ctx && ctx->start) {
        ret = ctx->start(ctx->param);
    }
    if (ctx && ctx->slot_index >= 0 && ctx->slot_index < MAX_THREADS) {
        sem_post(&thread_table[ctx->slot_index].done_sem);
    }
    free(ctx);
    return (void *)(uintptr_t)ret;
}

HANDLE CreateThread(void *lpThreadAttributes,
                    size_t dwStackSize,
                    LPTHREAD_START_ROUTINE lpStartAddress,
                    LPVOID lpParameter,
                    DWORD dwCreationFlags,
                    DWORD *lpThreadId) {
    (void)lpThreadAttributes;
    (void)dwCreationFlags;

    if (!lpStartAddress) {
        tls_last_error = ERROR_INVALID_HANDLE;
        return NULL;
    }

    pthread_mutex_lock(&g_thread_lock);
    int idx = -1;
    for (int i = 0; i < MAX_THREADS; i++) {
        if (!thread_table[i].in_use) {
            idx = i;
            thread_table[i].in_use = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_thread_lock);

    if (idx < 0) {
        tls_last_error = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }

    if (sem_init(&thread_table[idx].done_sem, 0, 0) != 0) {
        pthread_mutex_lock(&g_thread_lock);
        thread_table[idx].in_use = 0;
        pthread_mutex_unlock(&g_thread_lock);
        tls_last_error = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }

    ThreadStartCtx *ctx = (ThreadStartCtx *)calloc(1, sizeof(ThreadStartCtx));
    if (!ctx) {
        sem_destroy(&thread_table[idx].done_sem);
        pthread_mutex_lock(&g_thread_lock);
        thread_table[idx].in_use = 0;
        pthread_mutex_unlock(&g_thread_lock);
        tls_last_error = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }

    ctx->start = lpStartAddress;
    ctx->param = lpParameter;
    ctx->slot_index = idx;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    if (dwStackSize > 0) {
        pthread_attr_setstacksize(&attr, dwStackSize);
    }

    int rc = pthread_create(&thread_table[idx].thread, &attr, thread_start_trampoline, ctx);
    pthread_attr_destroy(&attr);

    if (rc != 0) {
        free(ctx);
        sem_destroy(&thread_table[idx].done_sem);
        pthread_mutex_lock(&g_thread_lock);
        thread_table[idx].in_use = 0;
        pthread_mutex_unlock(&g_thread_lock);
        tls_last_error = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }

    if (lpThreadId) {
        *lpThreadId = (DWORD)thread_table[idx].thread;
    }

    return index_to_handle(idx);
}

void ExitThread(DWORD dwExitCode) {
    pthread_exit((void *)(uintptr_t)dwExitCode);
}

DWORD GetCurrentThreadId(void) {
    return (DWORD)(uintptr_t)pthread_self();
}

DWORD GetCurrentProcessId(void) {
    return (DWORD)getpid();
}

DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    int idx = handle_to_index(hHandle);
    if (idx < 0 || idx >= MAX_THREADS) {
        tls_last_error = ERROR_INVALID_HANDLE;
        return WAIT_FAILED;
    }

    pthread_mutex_lock(&g_thread_lock);
    if (!thread_table[idx].in_use) {
        pthread_mutex_unlock(&g_thread_lock);
        tls_last_error = ERROR_INVALID_HANDLE;
        return WAIT_FAILED;
    }
    sem_t *sem = &thread_table[idx].done_sem;
    pthread_mutex_unlock(&g_thread_lock);

    if (dwMilliseconds == INFINITE) {
        while (sem_wait(sem) == -1) {
            if (errno != EINTR) {
                tls_last_error = ERROR_INVALID_HANDLE;
                return WAIT_FAILED;
            }
        }
        return WAIT_OBJECT_0;
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        tls_last_error = ERROR_INVALID_HANDLE;
        return WAIT_FAILED;
    }

    ts.tv_sec += dwMilliseconds / 1000;
    ts.tv_nsec += (long)(dwMilliseconds % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    while (sem_timedwait(sem, &ts) == -1) {
        if (errno == ETIMEDOUT) return WAIT_TIMEOUT;
        if (errno != EINTR) {
            tls_last_error = ERROR_INVALID_HANDLE;
            return WAIT_FAILED;
        }
    }
    return WAIT_OBJECT_0;
}

BOOL CloseHandle(HANDLE hObject) {
    int idx = handle_to_index(hObject);
    if (idx < 0 || idx >= MAX_THREADS) {
        tls_last_error = ERROR_INVALID_HANDLE;
        return FALSE;
    }

    pthread_mutex_lock(&g_thread_lock);
    if (!thread_table[idx].in_use) {
        pthread_mutex_unlock(&g_thread_lock);
        tls_last_error = ERROR_INVALID_HANDLE;
        return FALSE;
    }
    pthread_t th = thread_table[idx].thread;
    sem_t *sem = &thread_table[idx].done_sem;
    thread_table[idx].in_use = 0;
    pthread_mutex_unlock(&g_thread_lock);

    pthread_join(th, NULL);
    sem_destroy(sem);
    return TRUE;
}

void Sleep(DWORD dwMilliseconds) {
    struct timespec ts;
    ts.tv_sec = dwMilliseconds / 1000;
    ts.tv_nsec = (long)(dwMilliseconds % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

DWORD GetLastError(void) {
    return tls_last_error;
}

void SetLastError(DWORD e) {
    tls_last_error = e;
}
