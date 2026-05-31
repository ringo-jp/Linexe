#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ucontext.h>
#include <stdint.h>
#include <stdbool.h>
#include <setjmp.h>

#define SEH_LOG(fmt, ...) printf("[LINEXE/SEH] " fmt "\n", ##__VA_ARGS__)

// Windowsの例外コード定義
#define WIN_STATUS_ACCESS_VIOLATION          ((uint32_t)0xC0000005)
#define WIN_STATUS_INTEGER_DIVIDE_BY_ZERO   ((uint32_t)0xC0000094)
#define WIN_STATUS_ILLEGAL_INSTRUCTION       ((uint32_t)0xC000001D)
#define WIN_STATUS_STACK_OVERFLOW           ((uint32_t)0xC00000FD)

// スレッドローカルに現在の例外処理用ジャンプバッファを置く (マルチスレッド対応)
static __thread sigjmp_t g_seh_jump_env;
static __thread bool     g_seh_try_active = false;
static __thread uint32_t g_last_exception_code = 0;

// Windows風のコンテキスト保存用
typedef struct {
    uint64_t Rip;
    uint64_t Rsp;
    uint64_t Rax;
    uint64_t Rbx;
    uint64_t Rcx;
    uint64_t Rdx;
} LxCpuContext;

static __thread LxCpuContext g_last_cpu_context = {0};

/* ════════════════════════════════════════════════
   1. シグナルからSEHへの翻訳コアハンドラ
   ════════════════════════════════════════════════ */
static void linexe_signal_to_seh_dispatcher(int sig, siginfo_t* si, void* context) {
    ucontext_t* uc = (ucontext_t*)context;
    uint64_t fault_address = (uint64_t)si->si_addr;
    uint64_t rip = uc->uc_mcontext.gregs[REG_RIP];
    
    // CPUコンテキストの退避
    g_last_cpu_context.Rip = rip;
    g_last_cpu_context.Rsp = uc->uc_mcontext.gregs[REG_RSP];
    g_last_cpu_context.Rax = uc->uc_mcontext.gregs[REG_RAX];
    g_last_cpu_context.Rbx = uc->uc_mcontext.gregs[REG_RBX];
    g_last_cpu_context.Rcx = uc->uc_mcontext.gregs[REG_RCX];
    g_last_cpu_context.Rdx = uc->uc_mcontext.gregs[REG_RDX];

    uint32_t win_code = 0;

    switch (sig) {
        case SIGSEGV:
            win_code = WIN_STATUS_ACCESS_VIOLATION;
            SEH_LOG("CRITICAL: Segment Fault (Null pointer or memory violation) at address: %p", si->si_addr);
            break;
        case SIGFPE:
            win_code = WIN_STATUS_INTEGER_DIVIDE_BY_ZERO;
            SEH_LOG("CRITICAL: Math Exception (Divide by Zero) at Instruction: 0x%llx", (unsigned long long)rip);
            break;
        case SIGILL:
            win_code = WIN_STATUS_ILLEGAL_INSTRUCTION;
            SEH_LOG("CRITICAL: Illegal Instruction executed at Instruction: 0x%llx", (unsigned long long)rip);
            break;
        default:
            win_code = 0xC0000001; // 一般的な障害
            SEH_LOG("CRITICAL: Unhandled native signal %d caught.", sig);
    }

    g_last_exception_code = win_code;

    // アプリが __try マクロブロックの中にいる場合、クラッシュを防止してその例外ハンドラに復帰させる
    if (g_seh_try_active) {
        SEH_LOG("  -> [Bypass Recovery] Safely redirecting control flow to guest's __except block.");
        g_seh_try_active = false; // 二重例外防止
        siglongjmp(g_seh_jump_env, (int)win_code);
    } else {
        // 例外ハンドラがない場合は即死させず、詳細情報をダンプして終了コードとともに終了する
        SEH_LOG("  -> [Crash Guard] No SEH handler registered for this scope! Thread terminating safely.");
        SEH_LOG("  -> [DUMP] RAX:0x%llx RBX:0x%llx RCX:0x%llx RDX:0x%llx", 
                (unsigned long long)g_last_cpu_context.Rax, 
                (unsigned long long)g_last_cpu_context.Rbx, 
                (unsigned long long)g_last_cpu_context.Rcx, 
                (unsigned long long)g_last_cpu_context.Rdx);
        exit((int)win_code);
    }
}

/* ════════════════════════════════════════════════
   2. 例外処理ハンドラーAPI（テストおよび内部制御用）
   ════════════════════════════════════════════════ */

// ローダーが起動した瞬間にこのトラップを登録する
void linexe_init_seh_bridge(void) {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK; // 代替スタックを使用（スタック破壊対策）
    sa.sa_sigaction = linexe_signal_to_seh_dispatcher;
    sigemptyset(&sa.sa_mask);

    // Linuxのデスシグナルをすべてトラップ
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);

    SEH_LOG("Linux-to-Windows Structured Exception Handling (SEH) Bridge is now ACTIVE.");
}

// 疑似 __try マクロをサポートするための関数
sigjmp_t* linexe_seh_enter_try(void) {
    g_seh_try_active = true;
    return &g_seh_jump_env;
}

void linexe_seh_exit_try(void) {
    g_seh_try_active = false;
}

uint32_t linexe_seh_get_last_code(void) {
    return g_last_exception_code;
}

void linexe_seh_get_context(LxCpuContext* out_ctx) {
    if (out_ctx) {
        *out_ctx = g_last_cpu_context;
    }
}
