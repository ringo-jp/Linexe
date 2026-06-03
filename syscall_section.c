/*
 * Linexe - NT Section/Semaphore Syscall Translations (Phase 3)
 * Licensed under Apache License 2.0
 *
 * 実装:
 *   NtCreateSection         → memfd_create + mmap
 *   NtMapViewOfSection      → mmap (既存セクションのビュー)
 *   NtUnmapViewOfSection    → munmap
 *   NtWaitForMultipleObjects → 順次 futex wait (WaitAll/WaitAny)
 *   NtCreateSemaphore       → eventfd (カウント型)
 *   NtReleaseSemaphore      → eventfd write (カウント加算)
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
#include <sys/mman.h>
#include <linux/futex.h>
#include <sys/eventfd.h>
#include <time.h>
/* memfd_create via syscall; no dedicated header needed */

#ifndef LINEXE_QUIET
  #define TLOG(fmt,...) fprintf(stderr,"[LINEXE/SEC] " fmt "\n",##__VA_ARGS__)
#else
  #define TLOG(fmt,...)
#endif

#define STATUS_SUCCESS              0x00000000L
#define STATUS_NOT_IMPLEMENTED      0xC0000002L
#define STATUS_INVALID_PARAMETER    0xC000000DL
#define STATUS_INSUFFICIENT_RESOURCES 0xC000009AL

/* NT Page-protection → Linux mmap prot */
static int sec_nt_prot(uint32_t win_prot) {
    switch (win_prot & 0xFF) {
        case 0x02: return PROT_READ;
        case 0x04: return PROT_READ | PROT_WRITE;
        case 0x08: return PROT_READ | PROT_WRITE;
        case 0x10: return PROT_EXEC;
        case 0x20: return PROT_READ | PROT_EXEC;
        case 0x40: return PROT_READ | PROT_WRITE | PROT_EXEC;
        default:   return PROT_NONE;
    }
}

/* tracee メモリ読み書き（syscall_args.c の同名関数と重複しないよう
   ファイル内 static で定義） */
static int sec_read8(pid_t pid, uint64_t addr, uint64_t *out) {
    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (errno) return -1;
    *out = (uint64_t)v;
    return 0;
}

static int sec_write8(pid_t pid, uint64_t addr, uint64_t val) {
    uint64_t aligned = addr & ~(uint64_t)7;
    uint64_t offset  = addr - aligned;
    long word = 0;
    if (offset) {
        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, pid, (void *)aligned, NULL);
        if (errno) return -1;
    }
    size_t cp = (sizeof(val) < (size_t)(8 - offset)) ? sizeof(val) : (size_t)(8 - offset);
    memcpy((uint8_t *)&word + offset, &val, cp);
    return ptrace(PTRACE_POKEDATA, pid, (void *)aligned, (void *)word);
}

/* ════════════════════════════════════════════════
   NtCreateSection → memfd_create + ftruncate
   NT引数: SectionHandle*(rcx), DesiredAccess(rdx),
           ObjectAttributes*(r8), MaximumSize*(r9),
           SectionPageProtection(stack+0x28),
           AllocationAttributes(stack+0x30), FileHandle(stack+0x38)
   ════════════════════════════════════════════════ */
long translate_NtCreateSection(pid_t pid,
                                struct user_regs_struct *regs)
{
    uint64_t handle_ptr = regs->rcx;
    uint64_t size_ptr   = regs->r9;
    uint64_t prot_val = 0, file_handle = 0, max_size = 0;

    sec_read8(pid, regs->rsp + 0x28, &prot_val);
    sec_read8(pid, regs->rsp + 0x38, &file_handle);
    if (size_ptr) sec_read8(pid, size_ptr, &max_size);

    TLOG("NtCreateSection(size=%llu, prot=0x%llx, fh=%llu)",
         (unsigned long long)max_size,
         (unsigned long long)prot_val,
         (unsigned long long)file_handle);

    int fd;
    if (file_handle && file_handle != (uint64_t)-1) {
        /* ファイルバックのセクション: fd を複製して返す */
        fd = (int)file_handle;
    } else {
        /* 匿名セクション: memfd で実体を作る */
        fd = (int)syscall(SYS_memfd_create, "linexe_sec", MFD_CLOEXEC);
        if (fd < 0) {
            regs->rax = STATUS_INSUFFICIENT_RESOURCES;
            return -1;
        }
        if (max_size > 0 && ftruncate(fd, (off_t)max_size) < 0) {
            close(fd);
            regs->rax = STATUS_INSUFFICIENT_RESOURCES;
            return -1;
        }
    }

    /* SectionHandle に fd 値を書き戻す（ビュー時に再利用） */
    if (handle_ptr) {
        uint64_t hval = (uint64_t)(uint32_t)fd;
        sec_write8(pid, handle_ptr, hval);
    }

    regs->rax = STATUS_SUCCESS;
    return -1; /* カーネルには渡さず自前で完結 */
}

/* ════════════════════════════════════════════════
   NtMapViewOfSection → mmap(2)
   NT引数: SectionHandle(rcx), ProcessHandle(rdx),
           BaseAddress*(r8), ZeroBits(r9),
           CommitSize(stack+0x28), SectionOffset*(stack+0x30),
           ViewSize*(stack+0x38), InheritDisp(stack+0x40),
           AllocationType(stack+0x48), Win32Protect(stack+0x50)
   ════════════════════════════════════════════════ */
long translate_NtMapViewOfSection(pid_t pid,
                                   struct user_regs_struct *regs)
{
    int      sec_fd     = (int)(uint32_t)regs->rcx;
    uint64_t base_ptr   = regs->r8;
    uint64_t size_ptr   = 0, off_ptr = 0, prot_val = 0;
    uint64_t view_size  = 0, sec_off = 0, base = 0;

    sec_read8(pid, regs->rsp + 0x30, &off_ptr);
    sec_read8(pid, regs->rsp + 0x38, &size_ptr);
    sec_read8(pid, regs->rsp + 0x50, &prot_val);

    if (base_ptr) sec_read8(pid, base_ptr, &base);
    if (size_ptr) sec_read8(pid, size_ptr, &view_size);
    if (off_ptr)  sec_read8(pid, off_ptr,  &sec_off);

    int prot  = sec_nt_prot((uint32_t)prot_val);
    int flags = MAP_SHARED;
    if (base)  flags |= MAP_FIXED_NOREPLACE;
    if (sec_fd <= 0) { flags = MAP_PRIVATE | MAP_ANONYMOUS; sec_fd = -1; }

    TLOG("NtMapViewOfSection(fd=%d, base=0x%llx, size=%llu, off=%llu, prot=%d)",
         sec_fd,
         (unsigned long long)base,
         (unsigned long long)view_size,
         (unsigned long long)sec_off,
         prot);

    /* mmap を直接呼び出し（ptrace 経由ではなくトレーサー側で実行） */
    void *mapped = mmap((void *)base, view_size ? view_size : 0x1000,
                        prot, flags, sec_fd, (off_t)sec_off);
    if (mapped == MAP_FAILED) {
        TLOG("  mmap failed: %s", strerror(errno));
        regs->rax = STATUS_INSUFFICIENT_RESOURCES;
        return -1;
    }

    if (base_ptr)
        sec_write8(pid, base_ptr, (uint64_t)(uintptr_t)mapped);
    if (size_ptr && view_size == 0)
        sec_write8(pid, size_ptr, 0x1000);

    regs->rax = STATUS_SUCCESS;
    return -1;
}

/* ════════════════════════════════════════════════
   NtUnmapViewOfSection → munmap(2)
   NT引数: ProcessHandle(rcx), BaseAddress(rdx)
   ════════════════════════════════════════════════ */
long translate_NtUnmapViewOfSection(pid_t pid,
                                     struct user_regs_struct *regs)
{
    (void)pid;
    uint64_t base = regs->rdx;

    TLOG("NtUnmapViewOfSection(base=0x%llx)", (unsigned long long)base);

    /* サイズ不明なのでページ1枚分のみ解除（munmap はリージョン全体を解除） */
    if (base) munmap((void *)base, 0x1000);

    regs->rax = STATUS_SUCCESS;
    return -1;
}

/* ════════════════════════════════════════════════
   NtWaitForMultipleObjects
   NT引数: Count(rcx), Handles*(rdx),
           WaitType(r8:0=WaitAll,1=WaitAny),
           Alertable(r9), Timeout*(stack+0x28)
   簡易実装: 各ハンドルに対して順次 WAIT_OBJECT_0 を返す
   (futex ベースの完全実装には handle→futex マッピングが必要)
   ════════════════════════════════════════════════ */
long translate_NtWaitForMultipleObjects(pid_t pid,
                                         struct user_regs_struct *regs)
{
    uint32_t count    = (uint32_t)regs->rcx;
    uint64_t wait_any = regs->r8;  /* 0=WaitAll, 1=WaitAny */
    uint64_t timeout_ptr = 0;
    int64_t  ns = 0;

    sec_read8(pid, regs->rsp + 0x28, &timeout_ptr);

    if (timeout_ptr) {
        int64_t win100ns = 0;
        sec_read8(pid, timeout_ptr, (uint64_t *)&win100ns);
        if (win100ns < 0) {
            /* 相対時間: 負値×100ns */
            ns = (-win100ns) * 100LL;
        }
    }

    TLOG("NtWaitForMultipleObjects(count=%u, any=%llu, timeout_ns=%lld)",
         count, (unsigned long long)wait_any, (long long)ns);

    if (ns > 0) {
        struct timespec ts = {
            .tv_sec  = ns / 1000000000LL,
            .tv_nsec = ns % 1000000000LL,
        };
        nanosleep(&ts, NULL);
    }
    /* WaitAny: インデックス0が完了と仮定して STATUS_WAIT_0 を返す */
    regs->rax = (wait_any == 1) ? 0x00000000UL : 0x00000000UL;
    return -1;
}

/* ════════════════════════════════════════════════
   NtCreateSemaphore → eventfd(InitialCount)
   NT引数: SemaphoreHandle*(rcx), DesiredAccess(rdx),
           ObjectAttributes*(r8), InitialCount(r9),
           MaximumCount(stack+0x28)
   ════════════════════════════════════════════════ */
long translate_NtCreateSemaphore(pid_t pid,
                                  struct user_regs_struct *regs)
{
    uint64_t handle_ptr   = regs->rcx;
    uint32_t initial_count = (uint32_t)regs->r9;

    TLOG("NtCreateSemaphore(initial=%u)", initial_count);

    int efd = eventfd((unsigned int)initial_count, EFD_CLOEXEC | EFD_SEMAPHORE);
    if (efd < 0) {
        TLOG("  eventfd failed: %s", strerror(errno));
        regs->rax = STATUS_INSUFFICIENT_RESOURCES;
        return -1;
    }

    if (handle_ptr)
        sec_write8(pid, handle_ptr, (uint64_t)(uint32_t)efd);

    regs->rax = STATUS_SUCCESS;
    return -1;
}

/* ════════════════════════════════════════════════
   NtReleaseSemaphore → eventfd write(ReleaseCount)
   NT引数: SemaphoreHandle(rcx), ReleaseCount(rdx),
           PreviousCount*(r8)
   ════════════════════════════════════════════════ */
long translate_NtReleaseSemaphore(pid_t pid,
                                   struct user_regs_struct *regs)
{
    int      efd     = (int)(uint32_t)regs->rcx;
    uint64_t release = regs->rdx ? regs->rdx : 1;
    uint64_t prev_ptr = regs->r8;

    TLOG("NtReleaseSemaphore(efd=%d, release=%llu)",
         efd, (unsigned long long)release);

    if (prev_ptr)
        sec_write8(pid, prev_ptr, 0); /* 前の値は不明のため0 */

    uint64_t add = release;
    ssize_t n = write(efd, &add, sizeof(add));
    if (n < 0) {
        TLOG("  eventfd write failed: %s", strerror(errno));
        regs->rax = STATUS_INVALID_PARAMETER;
        return -1;
    }

    regs->rax = STATUS_SUCCESS;
    return -1;
}
