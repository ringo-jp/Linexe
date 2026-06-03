/*
 * Linexe - NT Thread Syscall Translations (Phase 3)
 * Licensed under Apache License 2.0
 *
 * 実装:
 *   NtCreateThread         → clone(2) stub
 *   NtCreateThreadEx       → clone(2) stub
 *   NtSuspendThread        → tgkill(SIGSTOP)
 *   NtResumeThread         → tgkill(SIGCONT)
 *   NtWaitForSingleObject  → translate2 への委譲
 *   NtQueryInformationThread → gettid stub
 *   NtSetInformationThread   → prctl stub
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/prctl.h>

#ifndef LINEXE_QUIET
  #define TLOG(fmt,...) fprintf(stderr,"[LINEXE/THR] " fmt "\n",##__VA_ARGS__)
#else
  #define TLOG(fmt,...)
#endif

#define STATUS_SUCCESS           0x00000000L
#define STATUS_NOT_IMPLEMENTED   0xC0000002L

static int st_write8(pid_t pid, uint64_t addr, uint64_t val) {
    /* aligned 8-byte write */
    uint64_t aligned = addr & ~(uint64_t)7;
    uint64_t offset  = addr - aligned;
    long word = 0;
    if (offset) {
        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, pid, (void *)aligned, NULL);
        if (errno) return -1;
    }
    memcpy((uint8_t *)&word + offset, &val, sizeof(val) > 8 - offset ? 8 - offset : sizeof(val));
    return ptrace(PTRACE_POKEDATA, pid, (void *)aligned, (void *)word);
}

/* ════════════════════════════════════════════════
   NtCreateThread / NtCreateThreadEx → clone(2) stub
   実際のスレッド生成はptrace環境下では複雑なため
   STATUS_NOT_IMPLEMENTED を返すスタブ。
   ════════════════════════════════════════════════ */
long translate_NtCreateThread(pid_t pid,
                               struct user_regs_struct *regs) {
    (void)pid;
    TLOG("NtCreateThread — stub (STATUS_NOT_IMPLEMENTED)");
    regs->orig_rax = SYS_getpid;
    regs->rax      = (uint64_t)(uint32_t)STATUS_NOT_IMPLEMENTED;
    return SYS_getpid;
}

long translate_NtCreateThreadEx(pid_t pid,
                                 struct user_regs_struct *regs) {
    (void)pid;
    TLOG("NtCreateThreadEx — stub (STATUS_NOT_IMPLEMENTED)");
    regs->orig_rax = SYS_getpid;
    regs->rax      = (uint64_t)(uint32_t)STATUS_NOT_IMPLEMENTED;
    return SYS_getpid;
}

/* ════════════════════════════════════════════════
   NtSuspendThread → kill(tid, SIGSTOP)
   NT引数: ThreadHandle(rcx), PreviousSuspendCount*(rdx)
   ════════════════════════════════════════════════ */
long translate_NtSuspendThread(pid_t pid,
                                struct user_regs_struct *regs) {
    uint64_t handle = regs->rcx;
    uint64_t prev_ptr = regs->rdx;

    TLOG("NtSuspendThread(handle=%llu)", (unsigned long long)handle);

    if (prev_ptr) {
        uint64_t zero = 0;
        st_write8(pid, prev_ptr, zero);
    }

    /* handle をtid として SIGSTOP を送信 */
    regs->orig_rax = SYS_tgkill;
    regs->rdi      = (uint64_t)pid;   /* tgid = tracer's target */
    regs->rsi      = handle;           /* tid */
    regs->rdx      = SIGSTOP;
    regs->rax      = SYS_tgkill;
    return SYS_tgkill;
}

/* ════════════════════════════════════════════════
   NtResumeThread → kill(tid, SIGCONT)
   NT引数: ThreadHandle(rcx), PreviousSuspendCount*(rdx)
   ════════════════════════════════════════════════ */
long translate_NtResumeThread(pid_t pid,
                               struct user_regs_struct *regs) {
    uint64_t handle  = regs->rcx;
    uint64_t prev_ptr = regs->rdx;

    TLOG("NtResumeThread(handle=%llu)", (unsigned long long)handle);

    if (prev_ptr) {
        uint64_t zero = 0;
        st_write8(pid, prev_ptr, zero);
    }

    regs->orig_rax = SYS_tgkill;
    regs->rdi      = (uint64_t)pid;
    regs->rsi      = handle;
    regs->rdx      = SIGCONT;
    regs->rax      = SYS_tgkill;
    return SYS_tgkill;
}

/* ════════════════════════════════════════════════
   NtWaitForSingleObject (non-translate2 alias)
   translate2_NtWaitForSingleObject に委譲する。
   ════════════════════════════════════════════════ */
long translate2_NtWaitForSingleObject(pid_t pid, struct user_regs_struct *regs);

long translate_NtWaitForSingleObject(pid_t pid,
                                      struct user_regs_struct *regs) {
    return translate2_NtWaitForSingleObject(pid, regs);
}

/* ════════════════════════════════════════════════
   NtQueryInformationThread → gettid stub
   NT引数: ThreadHandle(rcx), ThreadInformationClass(rdx),
           ThreadInformation*(r8), Length(r9), ReturnLength*(stack)
   ════════════════════════════════════════════════ */
long translate_NtQueryInformationThread(pid_t pid,
                                         struct user_regs_struct *regs) {
    uint64_t buf_ptr = regs->r8;

    TLOG("NtQueryInformationThread — gettid stub");

    if (buf_ptr) {
        uint64_t tid = (uint64_t)syscall(SYS_gettid);
        st_write8(pid, buf_ptr, tid);
    }

    regs->orig_rax = SYS_gettid;
    regs->rax      = SYS_gettid;
    return SYS_gettid;
}

/* ════════════════════════════════════════════════
   NtSetInformationThread → prctl stub
   NT引数: ThreadHandle(rcx), ThreadInformationClass(rdx),
           ThreadInformation*(r8), Length(r9)
   ════════════════════════════════════════════════ */
long translate_NtSetInformationThread(pid_t pid,
                                       struct user_regs_struct *regs) {
    (void)pid;
    TLOG("NtSetInformationThread — stub (STATUS_SUCCESS)");
    regs->orig_rax = SYS_getpid;
    regs->rax      = STATUS_SUCCESS;
    return SYS_getpid;
}
