/*
 * Linexe - NT Query/Registry Syscall Translations (Phase 3)
 * Licensed under Apache License 2.0
 *
 * 実装:
 *   NtQueryVirtualMemory    → mincore stub
 *   NtQuerySystemInformation → sysinfo/uname stub
 *   NtFlushVirtualMemory    → msync(2)
 *   NtOpenKey               → レジストリ stub
 *   NtCreateKey             → レジストリ stub
 *   NtQueryValueKey         → レジストリ stub
 *   NtEnumerateKey          → レジストリ stub
 *   NtEnumerateValueKey     → レジストリ stub
 *   NtSetValueKey           → レジストリ stub
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>

#ifndef LINEXE_QUIET
  #define TLOG(fmt,...) fprintf(stderr,"[LINEXE/QRY] " fmt "\n",##__VA_ARGS__)
#else
  #define TLOG(fmt,...)
#endif

#define STATUS_SUCCESS           0x00000000L
#define STATUS_NOT_IMPLEMENTED   0xC0000002L
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034L
#define STATUS_NO_MORE_ENTRIES   0x8000001AL

static int sq_write8(pid_t pid, uint64_t addr, uint64_t val) {
    uint64_t aligned = addr & ~(uint64_t)7;
    uint64_t offset  = addr - aligned;
    long word = 0;
    if (offset) {
        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, pid, (void *)aligned, NULL);
        if (errno) return -1;
    }
    size_t cp = sizeof(val) < 8 - offset ? sizeof(val) : 8 - offset;
    memcpy((uint8_t *)&word + offset, &val, cp);
    return ptrace(PTRACE_POKEDATA, pid, (void *)aligned, (void *)word);
}

/* ════════════════════════════════════════════════
   NtQueryVirtualMemory → MEMORY_BASIC_INFORMATION stub
   NT引数: ProcessHandle(rcx), BaseAddress*(rdx),
           MemoryInformationClass(r8), MemoryInformation*(r9),
           MemoryInformationLength(stack), ReturnLength*(stack)
   ════════════════════════════════════════════════ */
long translate_NtQueryVirtualMemory(pid_t pid,
                                     struct user_regs_struct *regs) {
    uint64_t base = regs->rdx;
    uint64_t buf  = regs->r9;

    TLOG("NtQueryVirtualMemory(base=0x%llx, buf=0x%llx)",
         (unsigned long long)base, (unsigned long long)buf);

    /* Write a minimal MEMORY_BASIC_INFORMATION: BaseAddress, RegionSize,
       State=MEM_COMMIT(0x1000), Protect=PAGE_READWRITE(0x04), Type=MEM_PRIVATE(0x20000) */
    if (buf) {
        uint64_t mbi[8] = {0};
        mbi[0] = base;           /* BaseAddress */
        mbi[1] = 0;              /* AllocationBase */
        mbi[2] = 0x04;           /* AllocationProtect = PAGE_READWRITE */
        mbi[3] = 0x1000;         /* RegionSize */
        mbi[4] = 0x1000;         /* State = MEM_COMMIT */
        mbi[5] = 0x04;           /* Protect = PAGE_READWRITE */
        mbi[6] = 0x20000;        /* Type = MEM_PRIVATE */
        for (int i = 0; i < 7; i++)
            sq_write8(pid, buf + (uint64_t)i * 8, mbi[i]);
    }

    regs->orig_rax = SYS_getpid;
    regs->rax      = STATUS_SUCCESS;
    return SYS_getpid;
}

/* ════════════════════════════════════════════════
   NtQuerySystemInformation → sysinfo stub
   NT引数: SystemInformationClass(rcx),
           SystemInformation*(rdx), Length(r8),
           ReturnLength*(r9)
   ════════════════════════════════════════════════ */
long translate_NtQuerySystemInformation(pid_t pid,
                                         struct user_regs_struct *regs) {
    uint64_t info_class = regs->rcx;
    uint64_t buf        = regs->rdx;

    TLOG("NtQuerySystemInformation(class=%llu)", (unsigned long long)info_class);

    /* SystemBasicInformation (class=0): fill minimal struct */
    if (info_class == 0 && buf) {
        /* SYSTEM_BASIC_INFORMATION simplified */
        uint64_t page_size = (uint64_t)sysconf(_SC_PAGE_SIZE);
        sq_write8(pid, buf,      0);           /* Reserved */
        sq_write8(pid, buf + 8,  page_size);   /* PageSize */
        sq_write8(pid, buf + 16, 0x1000);      /* MinimumUserModeAddress */
        sq_write8(pid, buf + 24, 0x7ffffffeffffULL); /* MaximumUserModeAddress */
    }

    regs->orig_rax = SYS_getpid;
    regs->rax      = STATUS_SUCCESS;
    return SYS_getpid;
}

/* ════════════════════════════════════════════════
   NtFlushVirtualMemory → msync(2)
   NT引数: ProcessHandle(rcx), BaseAddress*(rdx),
           RegionSize*(r8), IoStatusBlock*(r9)
   ════════════════════════════════════════════════ */
long translate_NtFlushVirtualMemory(pid_t pid,
                                     struct user_regs_struct *regs) {
    uint64_t base_ptr = regs->rdx;
    uint64_t size_ptr = regs->r8;

    uint64_t base = 0, size = 0;
    if (base_ptr) {
        errno = 0;
        long w = ptrace(PTRACE_PEEKDATA, pid, (void *)base_ptr, NULL);
        if (!errno) memcpy(&base, &w, 8);
    }
    if (size_ptr) {
        errno = 0;
        long w = ptrace(PTRACE_PEEKDATA, pid, (void *)size_ptr, NULL);
        if (!errno) memcpy(&size, &w, 8);
    }

    TLOG("NtFlushVirtualMemory(base=0x%llx, size=%llu)",
         (unsigned long long)base, (unsigned long long)size);

    regs->orig_rax = SYS_msync;
    regs->rdi      = base;
    regs->rsi      = size;
    regs->rdx      = MS_SYNC;
    regs->rax      = SYS_msync;
    return SYS_msync;
}

/* ════════════════════════════════════════════════
   Registry stubs — Linux にレジストリは存在しないため
   STATUS_OBJECT_NAME_NOT_FOUND / STATUS_NO_MORE_ENTRIES を返す
   ════════════════════════════════════════════════ */

long translate_NtOpenKey(pid_t pid, struct user_regs_struct *regs) {
    (void)pid;
    TLOG("NtOpenKey — stub (STATUS_OBJECT_NAME_NOT_FOUND)");
    regs->orig_rax = SYS_getpid;
    regs->rax      = (uint64_t)(uint32_t)STATUS_OBJECT_NAME_NOT_FOUND;
    return SYS_getpid;
}

long translate_NtCreateKey(pid_t pid, struct user_regs_struct *regs) {
    (void)pid;
    TLOG("NtCreateKey — stub (STATUS_NOT_IMPLEMENTED)");
    regs->orig_rax = SYS_getpid;
    regs->rax      = (uint64_t)(uint32_t)STATUS_NOT_IMPLEMENTED;
    return SYS_getpid;
}

long translate_NtQueryValueKey(pid_t pid, struct user_regs_struct *regs) {
    (void)pid;
    TLOG("NtQueryValueKey — stub (STATUS_OBJECT_NAME_NOT_FOUND)");
    regs->orig_rax = SYS_getpid;
    regs->rax      = (uint64_t)(uint32_t)STATUS_OBJECT_NAME_NOT_FOUND;
    return SYS_getpid;
}

long translate_NtEnumerateKey(pid_t pid, struct user_regs_struct *regs) {
    (void)pid;
    TLOG("NtEnumerateKey — stub (STATUS_NO_MORE_ENTRIES)");
    regs->orig_rax = SYS_getpid;
    regs->rax      = (uint64_t)(uint32_t)STATUS_NO_MORE_ENTRIES;
    return SYS_getpid;
}

long translate_NtEnumerateValueKey(pid_t pid, struct user_regs_struct *regs) {
    (void)pid;
    TLOG("NtEnumerateValueKey — stub (STATUS_NO_MORE_ENTRIES)");
    regs->orig_rax = SYS_getpid;
    regs->rax      = (uint64_t)(uint32_t)STATUS_NO_MORE_ENTRIES;
    return SYS_getpid;
}

long translate_NtSetValueKey(pid_t pid, struct user_regs_struct *regs) {
    (void)pid;
    TLOG("NtSetValueKey — stub (STATUS_NOT_IMPLEMENTED)");
    regs->orig_rax = SYS_getpid;
    regs->rax      = (uint64_t)(uint32_t)STATUS_NOT_IMPLEMENTED;
    return SYS_getpid;
}
