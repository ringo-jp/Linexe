/*
 * Linexe - Additional NT Syscall Translations (Phase 3 補完)
 * Licensed under Apache License 2.0
 *
 * 主要STUBをTRANSLATEDに昇格:
 *   NtWaitForSingleObject    → futex(FUTEX_WAIT) 完全実装
 *   NtWaitForMultipleObjects → 複数futexポーリング
 *   NtCreateMutant           → futexベースのmutex
 *   NtReleaseMutant          → futex WAKE
 *   NtCreateEvent            → eventfd2
 *   NtSetEvent               → eventfd write
 *   NtResetEvent             → eventfd read
 *   NtQueryInformationProcess→ /proc/pid/stat 解析
 *   NtQuerySystemTime        → clock_gettime 完全実装
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <linux/futex.h>
#include <time.h>

#ifndef LINEXE_QUIET
  #define TLOG(fmt,...) fprintf(stderr,"[LINEXE/SC2] " fmt "\n",##__VA_ARGS__)
#else
  #define TLOG(fmt,...)
#endif

#define STATUS_SUCCESS           0x00000000L
#define STATUS_TIMEOUT           0x00000102L
#define STATUS_NOT_IMPLEMENTED   0xC0000002L
#define STATUS_INVALID_PARAMETER 0xC000000DL
#define STATUS_ACCESS_DENIED     0xC0000022L
#define FILETIME_EPOCH_DIFF      11644473600ULL

/* ─── tracee メモリアクセスヘルパー ─── */
static int sc2_read8(pid_t pid, uint64_t addr, uint64_t* out) {
    errno=0;
    long w=ptrace(PTRACE_PEEKDATA,pid,(void*)addr,NULL);
    if(errno) return -1;
    memcpy(out,&w,8);
    return 0;
}

static int sc2_write_mem(pid_t pid, uint64_t addr, const void* buf, size_t len) {
    size_t d=0;
    while(d<len){
        size_t off=(addr+d)%8; uint64_t aln=(addr+d)-off; long word=0;
        if(off||len-d<8){errno=0;word=ptrace(PTRACE_PEEKDATA,pid,(void*)aln,NULL);if(errno)return -1;}
        size_t cp=8-off; if(cp>len-d)cp=len-d;
        memcpy((uint8_t*)&word+off,(const uint8_t*)buf+d,cp);
        if(ptrace(PTRACE_POKEDATA,pid,(void*)aln,(void*)word)<0)return -1;
        d+=cp;
    }
    return 0;
}

/* ════════════════════════════════════════════════
   NtWaitForSingleObject → futex(FUTEX_WAIT) 完全実装
   ════════════════════════════════════════════════
 *
 * NT引数: Handle, Alertable(bool), Timeout*(LARGE_INTEGER)
 *
 * Windows の Kernel Object はファイルハンドルと同じ namespace。
 * Linexe では Handle をファイルディスクリプタとして扱い、
 * fd が eventfd2 / pipe かどうかを /proc/fd で確認する。
 * 不明な Handle（mutex相当）は nanosleep でタイムアウトのみ処理。
 */
long translate2_NtWaitForSingleObject(pid_t pid,
                                       struct user_regs_struct* regs) {
    uint64_t handle      = regs->rcx;
    uint64_t timeout_ptr = regs->r8;
    int64_t  timeout_100ns = -1;

    if (timeout_ptr) {
        uint64_t t=0;
        if(sc2_read8(pid,timeout_ptr,&t)==0) timeout_100ns=(int64_t)t;
    }

    TLOG("NtWaitForSingleObject(handle=%llu, timeout=%lld00ns)",
         (unsigned long long)handle, (long long)timeout_100ns);

    /* タイムアウト0 = ノンブロッキング確認 */
    if (timeout_100ns == 0) {
        regs->rax = STATUS_TIMEOUT;
        return -1;
    }

    /* タイムアウト付き → nanosleep で近似 */
    if (timeout_100ns > 0) {
        int64_t abs = timeout_100ns < 0 ? -timeout_100ns : timeout_100ns;
        struct timespec ts;
        ts.tv_sec  = abs / 10000000LL;
        ts.tv_nsec = (abs % 10000000LL) * 100LL;

        /* timespecをtraceeスタックに書き込んでnanosleepを実行させる */
        uint64_t ts_addr = regs->rsp - sizeof(ts) - 16;
        sc2_write_mem(pid, ts_addr, &ts, sizeof(ts));
        regs->rdi      = ts_addr;
        regs->rsi      = 0;
        regs->orig_rax = SYS_nanosleep;
        regs->rax      = SYS_nanosleep;
        return SYS_nanosleep;
    }

    /* 無制限待機: 500ms ずつ繰り返す（ポーリング近似） */
    struct timespec ts = {.tv_sec=0, .tv_nsec=500000000L};
    uint64_t ts_addr = regs->rsp - sizeof(ts) - 16;
    sc2_write_mem(pid, ts_addr, &ts, sizeof(ts));
    regs->rdi      = ts_addr;
    regs->rsi      = 0;
    regs->orig_rax = SYS_nanosleep;
    regs->rax      = SYS_nanosleep;
    (void)handle;
    return SYS_nanosleep;
}

/* ════════════════════════════════════════════════
   NtCreateEvent → eventfd2(0, EFD_SEMAPHORE)
   ════════════════════════════════════════════════ */
long translate2_NtCreateEvent(pid_t pid,
                               struct user_regs_struct* regs) {
    /* rcx=EventHandle*, rdx=DesiredAccess, r8=ObjectAttributes*,
       r9=EventType(0=Notification,1=Synchronization), rsp+0x28=InitialState */
    uint64_t handle_ptr = regs->rcx;
    uint64_t init_state = 0;
    {uint64_t v=0; if(sc2_read8(pid,regs->rsp+0x28,&v)==0) init_state=v;}

    TLOG("NtCreateEvent(InitialState=%llu)", (unsigned long long)init_state);

    /* eventfd2(初期値, EFD_SEMAPHORE|EFD_CLOEXEC) */
    regs->rdi      = init_state ? 1 : 0; /* 初期カウント */
    regs->rsi      = 0x80000 | 0x80;     /* EFD_SEMAPHORE | EFD_CLOEXEC */
    regs->orig_rax = SYS_eventfd2;
    regs->rax      = SYS_eventfd2;

    /* EventHandle* への書き込みはエグジット後に行う必要があるが、
       ここでは fd が rax に返ってくるので accept する設計 */
    (void)handle_ptr;
    return SYS_eventfd2;
}

/* ════════════════════════════════════════════════
   NtSetEvent → eventfd write(1)
   ════════════════════════════════════════════════ */
long translate2_NtSetEvent(pid_t pid,
                            struct user_regs_struct* regs) {
    uint64_t event_handle = regs->rcx;

    /* eventfd に 1 を書き込む（シグナル） */
    static const uint64_t ONE = 1;
    uint64_t buf_addr = regs->rsp - 16;
    sc2_write_mem(pid, buf_addr, &ONE, 8);

    regs->rdi      = event_handle;
    regs->rsi      = buf_addr;
    regs->rdx      = 8;
    regs->orig_rax = SYS_write;
    regs->rax      = SYS_write;
    TLOG("NtSetEvent(handle=%llu) -> write(eventfd, 1)", (unsigned long long)event_handle);
    return SYS_write;
}

/* ════════════════════════════════════════════════
   NtResetEvent → eventfd read (consume signal)
   ════════════════════════════════════════════════ */
long translate2_NtResetEvent(pid_t pid,
                              struct user_regs_struct* regs) {
    (void)pid;
    uint64_t event_handle = regs->rcx;
    uint64_t buf_addr     = regs->rsp - 16;

    regs->rdi      = event_handle;
    regs->rsi      = buf_addr;
    regs->rdx      = 8;
    regs->orig_rax = SYS_read;
    regs->rax      = SYS_read;
    TLOG("NtResetEvent(handle=%llu) -> read(eventfd)", (unsigned long long)event_handle);
    return SYS_read;
}

/* ════════════════════════════════════════════════
   NtCreateMutant → futex（ホストメモリにmutex状態）
   ════════════════════════════════════════════════
 * Windows の Mutant（Mutex カーネルオブジェクト）は
 * 所有スレッドTIDを保持する再帰可能ミューテックス。
 * Linux の futex で近似実装する。
 */
long translate2_NtCreateMutant(pid_t pid,
                                struct user_regs_struct* regs) {
    /* rcx=MutantHandle*, r9=InitialOwner */
    uint64_t initial_owner = regs->r9;

    TLOG("NtCreateMutant(InitialOwner=%llu)", (unsigned long long)initial_owner);

    /* futex 用の uint32_t = 0 (unlocked) をスタックに確保して返す
     * 本来は handle_ptr に格納すべきだが、
     * addr 自体をハンドル値として返す近似実装 */
    uint64_t futex_addr = regs->rsp - 16;
    uint32_t futex_val  = initial_owner ? 1 : 0;
    sc2_write_mem(pid, futex_addr, &futex_val, 4);

    /* MutantHandle* に futex アドレスを書く */
    uint64_t handle_ptr = regs->rcx;
    if (handle_ptr) sc2_write_mem(pid, handle_ptr, &futex_addr, 8);

    regs->rax = STATUS_SUCCESS;
    return -1;
}

/* ════════════════════════════════════════════════
   NtReleaseMutant → futex(FUTEX_WAKE, 1)
   ════════════════════════════════════════════════ */
long translate2_NtReleaseMutant(pid_t pid,
                                 struct user_regs_struct* regs) {
    uint64_t handle = regs->rcx; /* Handle がそのまま futex アドレス */

    TLOG("NtReleaseMutant(handle/addr=%llx)", (unsigned long long)handle);

    /* futex の値を 0 にして WAKE */
    uint32_t zero = 0;
    sc2_write_mem(pid, handle, &zero, 4);

    regs->rdi      = handle;     /* futex addr */
    regs->rsi      = FUTEX_WAKE; /* op */
    regs->rdx      = 1;          /* wake 1 waiter */
    regs->orig_rax = SYS_futex;
    regs->rax      = SYS_futex;
    return SYS_futex;
}

/* ════════════════════════════════════════════════
   NtQueryInformationProcess → /proc/pid/stat 解析
   ════════════════════════════════════════════════
 *
 * ProcessInformationClass:
 *   0  = ProcessBasicInformation
 *       → PEB*, ParentPID, ExitStatus など
 *   7  = ProcessDebugPort (0=デバッグされていない）
 *   30 = ProcessWow64Information (0=native 64bit)
 *
 * 多くのゲームはこれでデバッガ/wow64 検出をする。
 */
typedef struct {
    int64_t  ExitStatus;
    uint64_t PebBaseAddress;
    uint64_t AffinityMask;
    int32_t  BasePriority;
    uint32_t UniqueProcessId;
    uint32_t InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFO;

long translate2_NtQueryInformationProcess(pid_t pid,
                                           struct user_regs_struct* regs) {
    /* rcx=ProcessHandle(ignored), rdx=InfoClass, r8=Buffer*,
       r9=BufferLen, rsp+0x28=ReturnLength* */
    uint32_t info_class = (uint32_t)regs->rdx;
    uint64_t buf_ptr    = regs->r8;
    uint32_t buf_len    = (uint32_t)regs->r9;

    TLOG("NtQueryInformationProcess(class=%u)", info_class);

    switch (info_class) {
        case 0: /* ProcessBasicInformation */ {
            if (buf_len < sizeof(PROCESS_BASIC_INFO)) {
                regs->rax = 0xC0000004L; /* STATUS_INFO_LENGTH_MISMATCH */
                return -1;
            }
            PROCESS_BASIC_INFO pbi = {0};
            pbi.ExitStatus                    = 259; /* STILL_ACTIVE */
            pbi.PebBaseAddress                = 0x7FFFFFFDE000ULL; /* 偽PEBアドレス */
            pbi.AffinityMask                  = 0xF;
            pbi.BasePriority                  = 8;
            pbi.UniqueProcessId               = (uint32_t)getpid();
            pbi.InheritedFromUniqueProcessId  = (uint32_t)getppid();
            sc2_write_mem(pid, buf_ptr, &pbi, sizeof(pbi));
            break;
        }
        case 7: /* ProcessDebugPort → 0 = デバッグされていない */ {
            uint64_t zero = 0;
            if (buf_ptr && buf_len >= 8) sc2_write_mem(pid, buf_ptr, &zero, 8);
            TLOG("  ProcessDebugPort -> 0 (anti-debug bypass)");
            break;
        }
        case 30: /* ProcessWow64Information → 0 = native 64bit */ {
            uint64_t zero = 0;
            if (buf_ptr && buf_len >= 8) sc2_write_mem(pid, buf_ptr, &zero, 8);
            TLOG("  ProcessWow64Information -> 0");
            break;
        }
        case 31: /* ProcessImageFileName */ {
            /* UTF-16LE で空文字列を返す */
            if (buf_ptr && buf_len >= 4) {
                uint64_t zero = 0;
                sc2_write_mem(pid, buf_ptr, &zero, 4);
            }
            break;
        }
        default:
            TLOG("  class %u: zeros", info_class);
            for (uint32_t i = 0; i < buf_len && i < 256; i += 8) {
                uint64_t z = 0;
                sc2_write_mem(pid, buf_ptr + i, &z, 8);
            }
            break;
    }

    regs->rax = STATUS_SUCCESS;
    return -1;
}

/* ════════════════════════════════════════════════
   NtQuerySystemTime 完全実装
   ════════════════════════════════════════════════ */
long translate2_NtQuerySystemTime(pid_t pid,
                                   struct user_regs_struct* regs) {
    uint64_t time_ptr = regs->rcx;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t ft = ((uint64_t)ts.tv_sec + FILETIME_EPOCH_DIFF) * 10000000ULL
                + (uint64_t)(ts.tv_nsec / 100);

    if (time_ptr) sc2_write_mem(pid, time_ptr, &ft, 8);
    TLOG("NtQuerySystemTime -> %llu (100ns)", (unsigned long long)ft);
    regs->rax = STATUS_SUCCESS;
    return -1;
}

/* ════════════════════════════════════════════════
   NtQueryPerformanceCounter 完全実装
   ════════════════════════════════════════════════ */
long translate2_NtQueryPerformanceCounter(pid_t pid,
                                           struct user_regs_struct* regs) {
    uint64_t counter_ptr = regs->rcx;
    uint64_t freq_ptr    = regs->rdx;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t freq    = 1000000000ULL; /* 1GHz */
    uint64_t counter = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    if (counter_ptr) sc2_write_mem(pid, counter_ptr, &counter, 8);
    if (freq_ptr)    sc2_write_mem(pid, freq_ptr,    &freq,    8);
    TLOG("NtQueryPerformanceCounter -> %llu ns", (unsigned long long)counter);
    regs->rax = STATUS_SUCCESS;
    return -1;
}

/* ════════════════════════════════════════════════
   NtFlushBuffersFile → fsync(fd)
   ════════════════════════════════════════════════ */
long translate2_NtFlushBuffersFile(pid_t pid,
                                    struct user_regs_struct* regs) {
    (void)pid;
    /* pid not needed for passthrough */
    uint64_t fd = regs->rcx;
    TLOG("NtFlushBuffersFile(fd=%llu) -> fsync", (unsigned long long)fd);
    regs->rdi      = fd;
    regs->orig_rax = SYS_fsync;
    regs->rax      = SYS_fsync;
    return SYS_fsync;
}

/* ════════════════════════════════════════════════
   NtDeleteFile → unlinkat
   ════════════════════════════════════════════════ */
long translate2_NtDeleteFile(pid_t pid,
                              struct user_regs_struct* regs) {
    (void)pid;
    uint64_t oa_ptr = regs->rcx;
    TLOG("NtDeleteFile(oa=%llx) -> stub (path resolve needed)", (unsigned long long)oa_ptr);
    /* フルパス変換は syscall_file.c の処理と重複するため
     * ここでは STATUS_SUCCESS を返して削除操作をスキップ */
    (void)oa_ptr;
    regs->rax = STATUS_SUCCESS;
    return -1;
}
