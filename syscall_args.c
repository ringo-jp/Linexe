/*
 * Linexe - NT Syscall Argument Translator (Phase 3)
 * Licensed under Apache License 2.0
 *
 * NTシステムコールの引数をLinuxシステムコールの引数に変換する。
 *
 * 引数レジスタ対応 (x86-64):
 *   Windows (NT ABI) : rcx, rdx, r8,  r9,  スタック...
 *   Linux (SysV ABI) : rdi, rsi, rdx, r10, r8, r9
 *
 * 各translate_Nt*関数:
 *   - 入力:  Windows NT呼び出し規約のregs
 *   - 出力:  Linux syscall呼び出し規約に書き換えたregs
 *   - 戻値:  実行するLinux syscall番号（-1 = エラー・スキップ）
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef LINEXE_QUIET
  #define TLOG(fmt, ...) fprintf(stderr, "[LINEXE/SC] " fmt "\n", ##__VA_ARGS__)
#else
  #define TLOG(fmt, ...)
#endif

/* ════════════════════════════════════════════════
   Windows NT 構造体 / フラグ定数
   ════════════════════════════════════════════════ */

/* NT Access Mask */
#define FILE_READ_DATA        0x00000001
#define FILE_WRITE_DATA       0x00000002
#define FILE_APPEND_DATA      0x00000004
#define GENERIC_READ          0x80000000
#define GENERIC_WRITE         0x40000000
#define GENERIC_ALL           0x10000000
#define DELETE                0x00010000

/* NT CreateDisposition */
#define FILE_SUPERSEDE        0
#define FILE_OPEN             1
#define FILE_CREATE           2
#define FILE_OPEN_IF          3
#define FILE_OVERWRITE        4
#define FILE_OVERWRITE_IF     5

/* NT CreateOptions */
#define FILE_DIRECTORY_FILE   0x00000001
#define FILE_NON_DIRECTORY_FILE 0x00000040

/* NT Memory flags */
#define MEM_COMMIT            0x00001000
#define MEM_RESERVE           0x00002000
#define MEM_RELEASE           0x00008000
#define MEM_DECOMMIT          0x00004000

/* NT Page protection → Linux prot */
#define PAGE_NOACCESS         0x01
#define PAGE_READONLY         0x02
#define PAGE_READWRITE        0x04
#define PAGE_EXECUTE          0x10
#define PAGE_EXECUTE_READ     0x20
#define PAGE_EXECUTE_READWRITE 0x40

/* UNICODE_STRING レイアウト（x64） */
typedef struct {
    uint16_t Length;
    uint16_t MaximumLength;
    uint32_t _pad;
    uint64_t Buffer; /* wchar_t* */
} UNICODE_STRING64;

/* OBJECT_ATTRIBUTES */
typedef struct {
    uint32_t Length;
    uint32_t _pad;
    uint64_t RootDirectory;
    uint64_t ObjectName; /* UNICODE_STRING64* */
    uint32_t Attributes;
    uint32_t _pad2;
    uint64_t SecurityDescriptor;
    uint64_t SecurityQualityOfService;
} OBJECT_ATTRIBUTES64;

/* IO_STATUS_BLOCK */
typedef struct {
    union { uint64_t Status; uint64_t Pointer; };
    uint64_t Information;
} IO_STATUS_BLOCK64;

/* ════════════════════════════════════════════════
   ユーティリティ：traced プロセスのメモリ読み取り
   ════════════════════════════════════════════════ */
#include <sys/ptrace.h>
#include <errno.h>

/*
 * tracee のメモリから最大 len バイトを読む。
 * ptrace(PTRACE_PEEKDATA) は 8バイト単位なので
 * バイト単位でアクセスする場合はループで対応する。
 */
static int read_tracee_mem(pid_t pid, uint64_t addr,
                            void* buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid,
                           (void*)(addr + done), NULL);
        if (errno != 0) return -1;

        size_t copy = len - done;
        if (copy > sizeof(long)) copy = sizeof(long);
        memcpy((uint8_t*)buf + done, &word, copy);
        done += copy;
    }
    return 0;
}

/*
 * tracee のメモリにデータを書く。
 * 8バイト単位で read-modify-write する。
 */
static int write_tracee_mem(pid_t pid, uint64_t addr,
                              const void* buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        size_t off   = (addr + done) % sizeof(long);
        uint64_t aligned = (addr + done) - off;
        long word;

        if (off != 0 || (len - done) < sizeof(long)) {
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, (void*)aligned, NULL);
            if (errno != 0) return -1;
        } else {
            word = 0;
        }

        size_t copy = sizeof(long) - off;
        if (copy > len - done) copy = len - done;
        memcpy((uint8_t*)&word + off, (const uint8_t*)buf + done, copy);

        if (ptrace(PTRACE_POKEDATA, pid, (void*)aligned, (void*)word) < 0)
            return -1;
        done += copy;
    }
    return 0;
}

/*
 * UNICODE_STRING を UTF-8 に変換（簡易版：ASCIIのみ）
 * Windows のパスは UTF-16LE なので、
 * 0x00XX のみのパスを ASCII として扱う。
 */
static int read_unicode_string(pid_t pid, uint64_t us_addr,
                                char* out, size_t outsz) {
    UNICODE_STRING64 us;
    if (read_tracee_mem(pid, us_addr, &us, sizeof(us)) < 0)
        return -1;

    uint16_t nbytes = us.Length;
    if (nbytes == 0 || nbytes > 4096) {
        out[0] = '\0';
        return 0;
    }

    /* UTF-16LE を一時バッファに読む */
    uint16_t* wbuf = malloc(nbytes + 2);
    if (!wbuf) return -1;
    if (read_tracee_mem(pid, us.Buffer, wbuf, nbytes) < 0) {
        free(wbuf); return -1;
    }
    wbuf[nbytes/2] = 0;

    /* ASCII変換（0x00XX のみ対応） */
    size_t i;
    for (i = 0; i < nbytes/2U && i < outsz - 1; i++) {
        out[i] = (wbuf[i] <= 0x7F) ? (char)wbuf[i] : '?';
    }
    out[i] = '\0';
    free(wbuf);
    return 0;
}

/* Windows NT Access Mask → Linux open flags */
static int nt_access_to_linux_flags(uint32_t access, uint32_t disposition) {
    int flags = 0;
    int r = (access & (FILE_READ_DATA  | GENERIC_READ  | GENERIC_ALL)) != 0;
    int w = (access & (FILE_WRITE_DATA | FILE_APPEND_DATA |
                       GENERIC_WRITE  | GENERIC_ALL | DELETE)) != 0;

    if (r && w) flags = O_RDWR;
    else if (w) flags = O_WRONLY;
    else        flags = O_RDONLY;

    switch (disposition) {
        case FILE_SUPERSEDE:    flags |= O_CREAT | O_TRUNC;   break;
        case FILE_CREATE:       flags |= O_CREAT | O_EXCL;    break;
        case FILE_OPEN_IF:      flags |= O_CREAT;             break;
        case FILE_OVERWRITE:    flags |= O_TRUNC;             break;
        case FILE_OVERWRITE_IF: flags |= O_CREAT | O_TRUNC;   break;
        case FILE_OPEN: /* そのまま */ break;
    }
    return flags;
}

/* Windows NT page protection → Linux mmap prot */
static int nt_page_to_prot(uint32_t win_prot) {
    switch (win_prot & 0xFF) {
        case PAGE_NOACCESS:          return PROT_NONE;
        case PAGE_READONLY:          return PROT_READ;
        case PAGE_READWRITE:         return PROT_READ | PROT_WRITE;
        case PAGE_EXECUTE:           return PROT_EXEC;
        case PAGE_EXECUTE_READ:      return PROT_EXEC | PROT_READ;
        case PAGE_EXECUTE_READWRITE: return PROT_EXEC | PROT_READ | PROT_WRITE;
        default:                     return PROT_READ | PROT_WRITE;
    }
}

/* Windows パス → Linux パス（簡易版） */
static void nt_path_to_linux(const char* nt, char* out, size_t outsz) {
    /* NT パスは \??\C:\... または \Device\HarddiskVolume... */
    const char* p = nt;
    if (strncmp(p, "\\??\\", 4) == 0)        p += 4;
    if (strncmp(p, "\\\\?\\", 4) == 0)       p += 4;

    const char* home = getenv("HOME");
    if (!home) home = "/tmp";

    if (p[1] == ':') {
        /* ドライブレター */
        snprintf(out, outsz, "%s/linexe_c/%s", home, p + 3);
        for (char* c = out; *c; c++) if (*c == '\\') *c = '/';
    } else if (strncmp(p, "\\Device\\", 8) == 0) {
        snprintf(out, outsz, "/tmp/linexe_dev/%s", p + 8);
        for (char* c = out; *c; c++) if (*c == '\\') *c = '/';
    } else {
        memcpy(out, p, outsz - 1); out[outsz-1] = '\0';
        out[outsz - 1] = '\0';
        for (char* c = out; *c; c++) if (*c == '\\') *c = '/';
    }
}

/* ════════════════════════════════════════════════
   個別変換関数
   引数: pid=tracee, regs=現在のレジスタ状態
   戻値: 実行するLinux syscall番号（-1=スキップ）
   ════════════════════════════════════════════════ */

/*
 * NtCreateFile / NtOpenFile → openat(2)
 *
 * NT引数 (rcx, rdx, r8, r9, stack...):
 *   FileHandle*  DesiredAccess  ObjectAttributes*
 *   IoStatusBlock*  AllocationSize  FileAttributes
 *   ShareAccess  CreateDisposition  CreateOptions
 *
 * Linux openat:
 *   rdi=AT_FDCWD, rsi=path*, rdx=flags, r10=mode
 */
static long translate_NtCreateFile(pid_t pid,
                                    struct user_regs_struct* regs) {
    /* NT引数はrcx(FileHandle*), rdx(DesiredAccess),
       r8(ObjectAttributes*), r9(IoStatusBlock*),
       スタック: AllocationSize, FileAttributes,
       ShareAccess, CreateDisposition, CreateOptions */
    uint32_t access      = (uint32_t)regs->rdx;
    uint64_t oa_ptr      = regs->r8;
    /* スタック上の引数: rsp+0x28（ホームスペース+ret後）*/
    uint64_t disp_addr   = regs->rsp + 0x30;
    uint64_t create_disp = 0;
    read_tracee_mem(pid, disp_addr, &create_disp, 8);

    /* ObjectAttributes から ObjectName を取得 */
    OBJECT_ATTRIBUTES64 oa;
    char nt_path[4096] = {0};
    char linux_path[4096] = {0};

    if (oa_ptr && read_tracee_mem(pid, oa_ptr, &oa, sizeof(oa)) == 0) {
        if (oa.ObjectName)
            read_unicode_string(pid, oa.ObjectName, nt_path, sizeof(nt_path));
    }

    nt_path_to_linux(nt_path, linux_path, sizeof(linux_path));
    TLOG("NtCreateFile(\"%s\") -> openat(\"%s\") disp=%llu",
         nt_path, linux_path, (unsigned long long)create_disp);

    /* linux_path をtraceeのスタックに書き込む */
    uint64_t str_addr = regs->rsp - 4096;
    write_tracee_mem(pid, str_addr, linux_path, strlen(linux_path) + 1);

    int flags = nt_access_to_linux_flags(access, (uint32_t)create_disp);

    /* Linux openat 引数をセット */
    regs->rdi = AT_FDCWD;          /* dirfd */
    regs->rsi = str_addr;           /* path* */
    regs->rdx = flags;              /* flags */
    regs->r10 = 0644;               /* mode */
    regs->orig_rax = SYS_openat;
    regs->rax      = SYS_openat;
    return SYS_openat;
}

/*
 * NtReadFile → read(2)
 *
 * NT引数: FileHandle, Event, ApcRoutine, ApcContext,
 *          IoStatusBlock*, Buffer*, Length,
 *          ByteOffset*, Key*
 * Linux:  rdi=fd, rsi=buf*, rdx=count
 */
static long translate_NtReadFile(pid_t pid,
                                  struct user_regs_struct* regs) {
    uint64_t fd     = regs->rcx;  /* FileHandle */
    uint64_t buf    = regs->r9;   /* Buffer (4th NT arg) */
    /* Lengthはスタック rsp+0x28 */
    uint64_t len = 0;
    read_tracee_mem(pid, regs->rsp + 0x28, &len, 8);

    TLOG("NtReadFile(fd=%llu, buf=0x%llx, len=%llu)",
         (unsigned long long)fd,
         (unsigned long long)buf,
         (unsigned long long)len);

    regs->rdi      = fd;
    regs->rsi      = buf;
    regs->rdx      = len;
    regs->orig_rax = SYS_read;
    regs->rax      = SYS_read;
    return SYS_read;
}

/*
 * NtWriteFile → write(2)
 */
static long translate_NtWriteFile(pid_t pid,
                                   struct user_regs_struct* regs) {
    uint64_t fd  = regs->rcx;
    uint64_t buf = regs->r9;
    uint64_t len = 0;
    read_tracee_mem(pid, regs->rsp + 0x28, &len, 8);

    TLOG("NtWriteFile(fd=%llu, buf=0x%llx, len=%llu)",
         (unsigned long long)fd,
         (unsigned long long)buf,
         (unsigned long long)len);

    regs->rdi      = fd;
    regs->rsi      = buf;
    regs->rdx      = len;
    regs->orig_rax = SYS_write;
    regs->rax      = SYS_write;
    return SYS_write;
}

/*
 * NtClose → close(2)
 */
static long translate_NtClose(pid_t pid,
                               struct user_regs_struct* regs) {
    (void)pid;
    uint64_t fd = regs->rcx;
    TLOG("NtClose(fd=%llu)", (unsigned long long)fd);
    regs->rdi      = fd;
    regs->orig_rax = SYS_close;
    regs->rax      = SYS_close;
    return SYS_close;
}

/*
 * NtAllocateVirtualMemory → mmap(2)
 *
 * NT引数: ProcessHandle, BaseAddress*, ZeroBits,
 *          RegionSize*, AllocationType, Protect
 */
static long translate_NtAllocateVirtualMemory(pid_t pid,
                                               struct user_regs_struct* regs) {
    uint64_t base_ptr = regs->rdx;   /* BaseAddress* (in/out) */
    uint64_t size_ptr = regs->r9;    /* RegionSize* */
    /* AllocationType はスタック rsp+0x28 */
    uint64_t alloc_type = 0, protect = 0;
    read_tracee_mem(pid, regs->rsp + 0x28, &alloc_type, 8);
    read_tracee_mem(pid, regs->rsp + 0x30, &protect,    8);

    uint64_t base = 0, size = 0;
    if (base_ptr) read_tracee_mem(pid, base_ptr, &base, 8);
    if (size_ptr) read_tracee_mem(pid, size_ptr, &size, 8);

    int prot  = nt_page_to_prot((uint32_t)protect);
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (base) flags |= MAP_FIXED_NOREPLACE;

    TLOG("NtAllocateVirtualMemory(base=0x%llx, size=%llu, prot=%d)",
         (unsigned long long)base, (unsigned long long)size, prot);

    regs->rdi      = base;            /* addr */
    regs->rsi      = size;            /* length */
    regs->rdx      = prot;            /* prot */
    regs->r10      = flags;           /* flags */
    regs->r8       = (uint64_t)-1;    /* fd */
    regs->r9       = 0;               /* offset */
    regs->orig_rax = SYS_mmap;
    regs->rax      = SYS_mmap;
    return SYS_mmap;
}

/*
 * NtFreeVirtualMemory → munmap(2)
 *
 * NT引数: ProcessHandle, BaseAddress*, RegionSize*, FreeType
 */
static long translate_NtFreeVirtualMemory(pid_t pid,
                                           struct user_regs_struct* regs) {
    uint64_t base_ptr = regs->rdx;
    uint64_t size_ptr = regs->r8;
    uint64_t base = 0, size = 0;
    if (base_ptr) read_tracee_mem(pid, base_ptr, &base, 8);
    if (size_ptr) read_tracee_mem(pid, size_ptr, &size, 8);

    TLOG("NtFreeVirtualMemory(base=0x%llx, size=%llu)",
         (unsigned long long)base, (unsigned long long)size);

    regs->rdi      = base;
    regs->rsi      = size;
    regs->orig_rax = SYS_munmap;
    regs->rax      = SYS_munmap;
    return SYS_munmap;
}

/*
 * NtProtectVirtualMemory → mprotect(2)
 *
 * NT引数: ProcessHandle, BaseAddress*, RegionSize*,
 *          NewProtect, OldProtect*
 */
static long translate_NtProtectVirtualMemory(pid_t pid,
                                              struct user_regs_struct* regs) {
    uint64_t base_ptr = regs->rdx;
    uint64_t size_ptr = regs->r8;
    uint32_t new_prot = (uint32_t)regs->r9;
    uint64_t base = 0, size = 0;
    if (base_ptr) read_tracee_mem(pid, base_ptr, &base, 8);
    if (size_ptr) read_tracee_mem(pid, size_ptr, &size, 8);

    int prot = nt_page_to_prot(new_prot);
    TLOG("NtProtectVirtualMemory(base=0x%llx, size=%llu, prot=%d)",
         (unsigned long long)base, (unsigned long long)size, prot);

    regs->rdi      = base;
    regs->rsi      = size;
    regs->rdx      = prot;
    regs->orig_rax = SYS_mprotect;
    regs->rax      = SYS_mprotect;
    return SYS_mprotect;
}

/*
 * NtTerminateProcess → exit_group(2)
 *
 * NT引数: ProcessHandle, ExitStatus
 */
static long translate_NtTerminateProcess(pid_t pid,
                                          struct user_regs_struct* regs) {
    (void)pid;
    uint32_t exit_code = (uint32_t)regs->rdx;
    TLOG("NtTerminateProcess(exit=%u)", exit_code);
    regs->rdi      = exit_code;
    regs->orig_rax = SYS_exit_group;
    regs->rax      = SYS_exit_group;
    return SYS_exit_group;
}

/*
 * NtTerminateThread → exit(2)
 */
static long translate_NtTerminateThread(pid_t pid,
                                         struct user_regs_struct* regs) {
    (void)pid;
    uint32_t exit_code = (uint32_t)regs->rdx;
    TLOG("NtTerminateThread(exit=%u)", exit_code);
    regs->rdi      = exit_code;
    regs->orig_rax = SYS_exit;
    regs->rax      = SYS_exit;
    return SYS_exit;
}

/*
 * NtDelayExecution → nanosleep(2)
 *
 * NT引数: Alertable(bool), DelayInterval*(LARGE_INTEGER)
 * LARGE_INTEGER は 100ナノ秒単位の負値（相対）または正値（絶対）
 */
static long translate_NtDelayExecution(pid_t pid,
                                        struct user_regs_struct* regs) {
    uint64_t interval_ptr = regs->rdx;
    int64_t  interval_100ns = 0;

    if (interval_ptr)
        read_tracee_mem(pid, interval_ptr, &interval_100ns, 8);

    /* 負値 = 相対時間（絶対値を使う） */
    if (interval_100ns < 0) interval_100ns = -interval_100ns;

    /* 100ns単位 → struct timespec */
    struct timespec ts;
    ts.tv_sec  =  interval_100ns / 10000000LL;
    ts.tv_nsec = (interval_100ns % 10000000LL) * 100;

    TLOG("NtDelayExecution(%lld00ns = %lds %ldns)",
         (long long)interval_100ns, (long)ts.tv_sec, ts.tv_nsec);

    /* timespecをtraceeのスタックに書き込む */
    uint64_t ts_addr = regs->rsp - sizeof(ts) - 8;
    write_tracee_mem(pid, ts_addr, &ts, sizeof(ts));

    regs->rdi      = ts_addr;    /* req */
    regs->rsi      = 0;          /* rem = NULL */
    regs->orig_rax = SYS_nanosleep;
    regs->rax      = SYS_nanosleep;
    return SYS_nanosleep;
}

/* ════════════════════════════════════════════════
   ディスパッチャ
   NT syscall番号から対応する変換関数を呼び出す
   ════════════════════════════════════════════════ */
#include "syscall_table.h"

long linexe_translate_syscall(pid_t pid,
                               struct user_regs_struct* regs) {
    uint32_t nt_nr = (uint32_t)regs->orig_rax;
    const SC_ENTRY* e = sc_find(nt_nr);

    if (!e) {
        TLOG("UNKNOWN NT syscall 0x%04X — passthrough as-is", nt_nr);
        return (long)nt_nr; /* 未知はそのまま通す */
    }

    if (e->status == SC_BLOCKED) {
        TLOG("BLOCKED NT syscall %s (0x%04X)", e->nt_name, nt_nr);
        regs->rax = (uint64_t)(-1); /* EPERM */
        return -1;
    }

    if (e->status == SC_STUB) {
        TLOG("STUB %s (0x%04X) -> return 0", e->nt_name, nt_nr);
        regs->rax = 0;
        return -1; /* カーネルに渡さず0を返す */
    }

    if (e->status == SC_PASSTHROUGH && e->linux_number >= 0) {
        TLOG("PASSTHROUGH %s (0x%04X) -> Linux %ld",
             e->nt_name, nt_nr, e->linux_number);
        regs->orig_rax = e->linux_number;
        regs->rax      = e->linux_number;
        return e->linux_number;
    }

    /* SC_TRANSLATED: 個別の変換関数を呼ぶ */
    switch (nt_nr) {
        case 0x0055: return translate_NtCreateFile(pid, regs);
        case 0x0033: return translate_NtCreateFile(pid, regs); /* NtOpenFile */
        case 0x0006: return translate_NtReadFile(pid, regs);
        case 0x0008: return translate_NtWriteFile(pid, regs);
        case 0x000F: return translate_NtClose(pid, regs);
        case 0x0018: return translate_NtAllocateVirtualMemory(pid, regs);
        case 0x001E: return translate_NtFreeVirtualMemory(pid, regs);
        case 0x0050: return translate_NtProtectVirtualMemory(pid, regs);
        case 0x002C: return translate_NtTerminateProcess(pid, regs);
        case 0x0053: return translate_NtTerminateThread(pid, regs);
        case 0x0034: return translate_NtDelayExecution(pid, regs);
        default:
            TLOG("TRANSLATED entry for 0x%04X has no handler, stub", nt_nr);
            regs->rax = 0;
            return -1;
    }
}
