#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ucontext.h>
#include <stdint.h>
#include <stdbool.h>
#include <setjmp.h>
#include <unistd.h>

#ifndef __x86_64__
#error "This module (linexe_seh.c) is strictly designed and optimized for x86_64 architecture!"
#endif

#define SEH_LOG(fmt, ...) printf("[LINEXE/SEH] " fmt "\n", ##__VA_ARGS__)

/* ════════════════════════════════════════════════
   Windows 例外コード定義 (完全版マッピング用)
   ════════════════════════════════════════════════ */
#define WIN_STATUS_ACCESS_VIOLATION          ((uint32_t)0xC0000005)
#define WIN_STATUS_INTEGER_DIVIDE_BY_ZERO   ((uint32_t)0xC0000094)
#define WIN_STATUS_ILLEGAL_INSTRUCTION       ((uint32_t)0xC000001D)
#define WIN_STATUS_STACK_OVERFLOW           ((uint32_t)0xC00000FD)
#define WIN_STATUS_DATATYPE_MISALIGNMENT    ((uint32_t)0x80000002)
#define WIN_STATUS_BREAKPOINT               ((uint32_t)0x80000003)
#define WIN_STATUS_SINGLE_STEP              ((uint32_t)0x80000004)
#define WIN_STATUS_FLOAT_DIVIDE_BY_ZERO     ((uint32_t)0xC000008E)
#define WIN_STATUS_PRIVILEGED_INSTRUCTION    ((uint32_t)0xC0000096)
#define WIN_STATUS_IN_PAGE_ERROR            ((uint32_t)0xC0000006)

/* ════════════════════════════════════════════════
   C言語用 Windows SEH風 構文エミュレーションマクロ
   ════════════════════════════════════════════════ */
#define __try \
    do { \
        sigjmp_t* __env = linexe_seh_enter_try(); \
        if (sigsetjmp(*__env, 1) == 0) {

#define __except(filter) \
            linexe_seh_exit_try(); \
        } else { \
            linexe_seh_exit_try(); \
            uint32_t exception_code = linexe_seh_get_last_code(); \
            (void)exception_code; \
            if (filter) {

#define __end_try \
            } \
        } \
    } while(0)

// スレッドローカルの例外コンテキスト
static __thread sigjmp_t g_seh_jump_env;
static __thread bool     g_seh_try_active = false;
static __thread uint32_t g_last_exception_code = 0;

// Windows風コンテキスト構造体 (x86_64 全主要レジスタを完全カバー)
typedef struct {
    uint64_t Rip;
    uint64_t Rsp;
    uint64_t Rbp;
    uint64_t Rax;
    uint64_t Rbx;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rsi;
    uint64_t Rdi;
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;
    uint64_t EFlags;
} LxCpuContext;

static __thread LxCpuContext g_last_cpu_context = {0};

/* ════════════════════════════════════════════════
   1. シグナルからSEHへの翻訳コアハンドラ
   ════════════════════════════════════════════════ */
static void linexe_signal_to_seh_dispatcher(int sig, siginfo_t* si, void* context) {
    ucontext_t* uc = (ucontext_t*)context;
    uint64_t fault_address = (uint64_t)si->si_addr;
    uint64_t rip = uc->uc_mcontext.gregs[REG_RIP];
    uint64_t rsp = uc->uc_mcontext.gregs[REG_RSP];
    
    // CPUコンテキストの完全退避 (x86_64 特有のレジスタ配置を全てカバー)
    g_last_cpu_context.Rip    = rip;
    g_last_cpu_context.Rsp    = rsp;
    g_last_cpu_context.Rbp    = uc->uc_mcontext.gregs[REG_RBP];
    g_last_cpu_context.Rax    = uc->uc_mcontext.gregs[REG_RAX];
    g_last_cpu_context.Rbx    = uc->uc_mcontext.gregs[REG_RBX];
    g_last_cpu_context.Rcx    = uc->uc_mcontext.gregs[REG_RCX];
    g_last_cpu_context.Rdx    = uc->uc_mcontext.gregs[REG_RDX];
    g_last_cpu_context.Rsi    = uc->uc_mcontext.gregs[REG_RSI];
    g_last_cpu_context.Rdi    = uc->uc_mcontext.gregs[REG_RDI];
    g_last_cpu_context.R8     = uc->uc_mcontext.gregs[REG_R8];
    g_last_cpu_context.R9     = uc->uc_mcontext.gregs[REG_R9];
    g_last_cpu_context.R10    = uc->uc_mcontext.gregs[REG_R10];
    g_last_cpu_context.R11    = uc->uc_mcontext.gregs[REG_R11];
    g_last_cpu_context.R12    = uc->uc_mcontext.gregs[REG_R12];
    g_last_cpu_context.R13    = uc->uc_mcontext.gregs[REG_R13];
    g_last_cpu_context.R14    = uc->uc_mcontext.gregs[REG_R14];
    g_last_cpu_context.R15    = uc->uc_mcontext.gregs[REG_R15];
    g_last_cpu_context.EFlags = uc->uc_mcontext.gregs[REG_EFL];

    uint32_t win_code = 0;

    switch (sig) {
        case SIGSEGV: {
            // [スタックオーバーフロー判定ロジック]
            // フォールトアドレスがスタックポインタ(RSP)付近(通常ページサイズ 4KB 〜 数MBのガードバンド内)であり、
            // スタック保護領域を突き破ったアクセスを検知した場合
            uint64_t stack_dist = (rsp > fault_address) ? (rsp - fault_address) : (fault_address - rsp);
            if (stack_dist < 0x100000) { // RSPから1MB以内のページ違反はスタック枯渇とみなす
                win_code = WIN_STATUS_STACK_OVERFLOW;
                SEH_LOG("CRITICAL: Stack Overflow detected at RSP: 0x%llx, Bad Access: %p", 
                        (unsigned long long)rsp, si->si_addr);
            } else {
                win_code = WIN_STATUS_ACCESS_VIOLATION;
                SEH_LOG("CRITICAL: Segment Fault (Access Violation) at %p", si->si_addr);
            }
            break;
        }
        case SIGBUS:
            if (si->si_code == BUS_ADRALN) {
                win_code = WIN_STATUS_DATATYPE_MISALIGNMENT;
                SEH_LOG("CRITICAL: Alignment fault (Datatype Misalignment) at %p", si->si_addr);
            } else {
                win_code = WIN_STATUS_IN_PAGE_ERROR;
                SEH_LOG("CRITICAL: Bus error (In-Page Error) at %p", si->si_addr);
            }
            break;
        case SIGFPE:
            switch (si->si_code) {
                case FPE_INTDIV:
                    win_code = WIN_STATUS_INTEGER_DIVIDE_BY_ZERO;
                    SEH_LOG("CRITICAL: Integer Divide by Zero at Instruction: 0x%llx", (unsigned long long)rip);
                    break;
                case FPE_FLTDIV:
                    win_code = WIN_STATUS_FLOAT_DIVIDE_BY_ZERO;
                    SEH_LOG("CRITICAL: Float Divide by Zero at Instruction: 0x%llx", (unsigned long long)rip);
                    break;
                default:
                    win_code = WIN_STATUS_INTEGER_DIVIDE_BY_ZERO;
                    SEH_LOG("CRITICAL: Arithmetic Exception (FPE Code: %d)", si->si_code);
            }
            break;
        case SIGILL:
            if (si->si_code == ILL_PRVOPC || si->si_code == ILL_PRVREG) {
                win_code = WIN_STATUS_PRIVILEGED_INSTRUCTION;
                SEH_LOG("CRITICAL: Privileged Instruction executed at Instruction: 0x%llx", (unsigned long long)rip);
            } else {
                win_code = WIN_STATUS_ILLEGAL_INSTRUCTION;
                SEH_LOG("CRITICAL: Illegal Instruction executed at Instruction: 0x%llx", (unsigned long long)rip);
            }
            break;
        case SIGTRAP:
            win_code = WIN_STATUS_BREAKPOINT;
            SEH_LOG("CRITICAL: Hardware Breakpoint / Trap hit at Instruction: 0x%llx", (unsigned long long)rip);
            break;
        default:
            win_code = 0xC0000001; // STATUS_UNSUCCESSFUL
            SEH_LOG("CRITICAL: Unhandled native signal %d caught.", sig);
    }

    g_last_exception_code = win_code;

    // アプリが __try 内にいる場合、クラッシュをバイパスして例外ハンドラへ復帰
    if (g_seh_try_active) {
        SEH_LOG("  -> [Bypass Recovery] Safely redirecting control flow to __except block.");
        g_seh_try_active = false; // 二重例外抑止
        siglongjmp(g_seh_jump_env, (int)win_code);
    } else {
        SEH_LOG("  -> [Crash Guard] No SEH handler registered for this scope! Thread terminating safely.");
        SEH_LOG("  -> [x86_64 REG DUMP]\n"
                "     RAX:0x%016llx  RBX:0x%016llx  RCX:0x%016llx  RDX:0x%016llx\n"
                "     RSI:0x%016llx  RDI:0x%016llx  RBP:0x%016llx  RSP:0x%016llx\n"
                "     R8 :0x%016llx  R9 :0x%016llx  R10:0x%016llx  R11:0x%016llx\n"
                "     R12:0x%016llx  R13:0x%016llx  R14:0x%016llx  R15:0x%016llx\n"
                "     RIP:0x%016llx  EFLAGS:0x%08llx", 
                (unsigned long long)g_last_cpu_context.Rax, (unsigned long long)g_last_cpu_context.Rbx,
                (unsigned long long)g_last_cpu_context.Rcx, (unsigned long long)g_last_cpu_context.Rdx,
                (unsigned long long)g_last_cpu_context.Rsi, (unsigned long long)g_last_cpu_context.Rdi,
                (unsigned long long)g_last_cpu_context.Rbp, (unsigned long long)g_last_cpu_context.Rsp,
                (unsigned long long)g_last_cpu_context.R8,  (unsigned long long)g_last_cpu_context.R9,
                (unsigned long long)g_last_cpu_context.R10, (unsigned long long)g_last_cpu_context.R11,
                (unsigned long long)g_last_cpu_context.R12, (unsigned long long)g_last_cpu_context.R13,
                (unsigned long long)g_last_cpu_context.R14, (unsigned long long)g_last_cpu_context.R15,
                (unsigned long long)g_last_cpu_context.Rip, (unsigned long long)g_last_cpu_context.EFlags);
        exit((int)win_code);
    }
}

/* ════════════════════════════════════════════════
   2. 例外処理ハンドラーAPI（初期化・制御用）
   ════════════════════════════════════════════════ */

// ローダーが起動した瞬間にシグナルトラップと代替スタックを初期化する
void linexe_init_seh_bridge(void) {
    // [スタックオーバーフロー検出用代替スタックの設定]
    // 通常のスタック領域が枯渇した際、シグナルハンドラが正常に動作するための別スタックを確保
    stack_t alt_stack;
    alt_stack.ss_size = SIGSTKSZ * 4; // 余裕を持たせたサイズ (通常は8KBだが32KB割り当て)
    alt_stack.ss_sp = malloc(alt_stack.ss_size);
    alt_stack.ss_flags = 0;
    
    if (alt_stack.ss_sp) {
        if (sigaltstack(&alt_stack, NULL) == -1) {
            perror("[LINEXE/SEH] Failed to set alternate signal stack");
            free(alt_stack.ss_sp);
        } else {
            SEH_LOG("Alternate stack configured successfully (Size: %zu bytes).", alt_stack.ss_size);
        }
    } else {
        SEH_LOG("Warning: Unable to allocate alternate stack memory.");
    }

    struct sigaction sa;
    // SA_ONSTACK を付与することで代替スタック上でハンドリングを行う
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER; 
    sa.sa_sigaction = linexe_signal_to_seh_dispatcher;
    sigemptyset(&sa.sa_mask);

    // Linuxのすべての致命的シグナルをLinexeでトラップ
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);

    SEH_LOG("Linux-to-Windows SEH Bridge is now ACTIVE (Optimized for x86_64).");
}

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
