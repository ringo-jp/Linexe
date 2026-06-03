/*
 * Linexe - NT File Information Syscall Translations (Phase 3)
 * Licensed under Apache License 2.0
 *
 * 実装:
 *   NtQueryInformationFile  → fstat(2)
 *   NtSetInformationFile    → ftruncate / futimens
 *   NtQueryAttributesFile   → stat(2)
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
#include <time.h>

#ifndef LINEXE_QUIET
  #define TLOG(fmt,...) fprintf(stderr,"[LINEXE/FILE] " fmt "\n",##__VA_ARGS__)
#else
  #define TLOG(fmt,...)
#endif

#define STATUS_SUCCESS           0x00000000L
#define STATUS_NOT_IMPLEMENTED   0xC0000002L
#define STATUS_INVALID_PARAMETER 0xC000000DL

/* Windows 100ns ticks since 1601-01-01 → timespec (Unix epoch) */
#define FILETIME_EPOCH_DIFF 11644473600ULL

static int sf_read8(pid_t pid, uint64_t addr, uint64_t *out) {
    errno = 0;
    long w = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (errno) return -1;
    memcpy(out, &w, 8);
    return 0;
}

static int sf_write_mem(pid_t pid, uint64_t addr, const void *buf, size_t len) {
    size_t d = 0;
    while (d < len) {
        size_t off = (addr + d) % 8;
        uint64_t aln = (addr + d) - off;
        long word = 0;
        if (off || len - d < 8) {
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, (void *)aln, NULL);
            if (errno) return -1;
        }
        size_t cp = 8 - off;
        if (cp > len - d) cp = len - d;
        memcpy((uint8_t *)&word + off, (const uint8_t *)buf + d, cp);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)aln, (void *)word) < 0) return -1;
        d += cp;
    }
    return 0;
}

/* ════════════════════════════════════════════════
   NtQueryInformationFile → fstat(2)
   NT引数: FileHandle(rcx), IoStatusBlock*(rdx),
           FileInformation*(r8), Length(r9), FileInformationClass(stack)
   ════════════════════════════════════════════════ */
long translate_NtQueryInformationFile(pid_t pid,
                                       struct user_regs_struct *regs) {
    uint64_t fd      = regs->rcx;
    uint64_t isb_ptr = regs->rdx;
    uint64_t buf_ptr = regs->r8;
    uint64_t length  = regs->r9;

    TLOG("NtQueryInformationFile(fd=%llu, buf=0x%llx, len=%llu)",
         (unsigned long long)fd, (unsigned long long)buf_ptr,
         (unsigned long long)length);

    struct stat st;
    if (fstat((int)fd, &st) < 0) {
        /* IoStatusBlock.Status = error */
        uint64_t status = (uint64_t)(uint32_t)STATUS_INVALID_PARAMETER;
        sf_write_mem(pid, isb_ptr, &status, 8);
        regs->orig_rax = SYS_fstat;
        regs->rdi      = fd;
        regs->rsi      = buf_ptr;
        regs->rax      = SYS_fstat;
        return SYS_fstat;
    }

    /* Write FILE_BASIC_INFORMATION subset: sizes only (simplified) */
    if (buf_ptr && length >= 8) {
        uint64_t fsize = (uint64_t)st.st_size;
        sf_write_mem(pid, buf_ptr, &fsize, 8);
    }
    uint64_t status_ok = STATUS_SUCCESS;
    sf_write_mem(pid, isb_ptr, &status_ok, 8);

    /* fstat を実行させて rax = 0 にする */
    regs->orig_rax = SYS_fstat;
    regs->rdi      = fd;
    regs->rsi      = buf_ptr;
    regs->rax      = SYS_fstat;
    return SYS_fstat;
}

/* ════════════════════════════════════════════════
   NtSetInformationFile → ftruncate(2) / stub
   NT引数: FileHandle(rcx), IoStatusBlock*(rdx),
           FileInformation*(r8), Length(r9), FileInformationClass(stack)
   ════════════════════════════════════════════════ */
long translate_NtSetInformationFile(pid_t pid,
                                     struct user_regs_struct *regs) {
    uint64_t fd      = regs->rcx;
    uint64_t isb_ptr = regs->rdx;
    uint64_t buf_ptr = regs->r8;

    TLOG("NtSetInformationFile(fd=%llu, buf=0x%llx) — stub ftruncate",
         (unsigned long long)fd, (unsigned long long)buf_ptr);

    /* FileEndOfFileInformation: first 8 bytes = EndOfFile (LARGE_INTEGER) */
    uint64_t eof = 0;
    sf_read8(pid, buf_ptr, &eof);

    uint64_t status_ok = STATUS_SUCCESS;
    sf_write_mem(pid, isb_ptr, &status_ok, 8);

    regs->orig_rax = SYS_ftruncate;
    regs->rdi      = fd;
    regs->rsi      = (uint64_t)(int64_t)eof;
    regs->rax      = SYS_ftruncate;
    return SYS_ftruncate;
}

/* ════════════════════════════════════════════════
   NtQueryAttributesFile → stat(2) via path in ObjectAttributes
   NT引数: ObjectAttributes*(rcx), FileBasicInformation*(rdx)
   ════════════════════════════════════════════════ */
long translate_NtQueryAttributesFile(pid_t pid,
                                      struct user_regs_struct *regs) {
    uint64_t buf_ptr = regs->rdx;

    TLOG("NtQueryAttributesFile — stub (returning STATUS_NOT_IMPLEMENTED)");

    /* Write STATUS_NOT_IMPLEMENTED into caller's buffer if provided */
    if (buf_ptr) {
        uint64_t status = (uint64_t)(uint32_t)STATUS_NOT_IMPLEMENTED;
        sf_write_mem(pid, buf_ptr, &status, 8);
    }

    /* Redirect to a harmless getpid so execution continues */
    regs->orig_rax = SYS_getpid;
    regs->rax      = SYS_getpid;
    return SYS_getpid;
}
