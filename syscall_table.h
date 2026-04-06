/*
 * Linexe - NT Syscall Translation Table (Phase 3)
 * Licensed under Apache License 2.0
 *
 * Windows 10 x64 (Build 19041+) の NTシステムコール番号を
 * Linuxシステムコール番号に対応させる変換テーブル。
 *
 * 参考：Windows NT syscall numbers (Win10 1903+, x64)
 *   https://j00ru.vexillium.org/syscalls/nt/64/
 *
 * 対応状況:
 *   TRANSLATED  = 引数変換まで実装済み
 *   PASSTHROUGH = 番号変換のみ（引数はそのまま）
 *   STUB        = テーブル登録済み・変換未実装（NOP返却）
 *   UNKNOWN     = 未知のシステムコール
 */

#ifndef LINEXE_SYSCALL_TABLE_H
#define LINEXE_SYSCALL_TABLE_H

#include <stdint.h>
#include <sys/syscall.h>

/* ════════════════════════════════════════════════
   変換ステータス
   ════════════════════════════════════════════════ */
typedef enum {
    SC_UNKNOWN     = 0,  /* 未知：パストルー試行 */
    SC_STUB        = 1,  /* テーブル登録済み・未実装：0返却 */
    SC_PASSTHROUGH = 2,  /* Linux番号に変換のみ */
    SC_TRANSLATED  = 3,  /* 完全な引数変換あり */
    SC_BLOCKED     = 4,  /* 実行禁止（危険なカーネル操作等） */
} SC_STATUS;

/* ════════════════════════════════════════════════
   変換エントリ
   ════════════════════════════════════════════════ */
typedef struct {
    uint32_t   nt_number;      /* Windows NT syscall番号 */
    const char* nt_name;       /* NT関数名 */
    long       linux_number;   /* 対応するLinux syscall番号（-1=対応なし） */
    const char* linux_name;    /* Linux関数名 */
    SC_STATUS  status;
} SC_ENTRY;

/* Linux syscallが存在しない場合のセンチネル */
#define SC_NO_LINUX (-1L)

/* ════════════════════════════════════════════════
   NTシステムコール変換テーブル (Windows 10 x64 19041+)
   ════════════════════════════════════════════════ */
static const SC_ENTRY SYSCALL_TABLE[] = {

    /* ── ファイル I/O ─────────────────────────── */
    { 0x0006, "NtReadFile",
      SYS_read,            "read",            SC_TRANSLATED  },
    { 0x0008, "NtWriteFile",
      SYS_write,           "write",           SC_TRANSLATED  },
    { 0x000F, "NtClose",
      SYS_close,           "close",           SC_TRANSLATED  },
    { 0x0011, "NtQueryInformationFile",
      SYS_newfstatat,      "newfstatat",      SC_STUB        },
    { 0x0033, "NtOpenFile",
      SYS_openat,          "openat",          SC_TRANSLATED  },
    { 0x0055, "NtCreateFile",
      SYS_openat,          "openat",          SC_TRANSLATED  },
    { 0x0057, "NtDeleteFile",
      SYS_unlinkat,        "unlinkat",        SC_TRANSLATED        },
    { 0x0070, "NtFlushBuffersFile",
      SYS_fsync,           "fsync",           SC_PASSTHROUGH },
    { 0x0073, "NtQueryVolumeInformationFile",
      SYS_statfs,          "statfs",          SC_TRANSLATED        },
    { 0x0027, "NtSetInformationFile",
      SYS_fcntl,           "fcntl",           SC_STUB        },
    { 0x0042, "NtCreateNamedPipeFile",
      SC_NO_LINUX,         "pipe2",           SC_STUB        },
    { 0x0052, "NtCancelIoFile",
      SC_NO_LINUX,         "(no direct)",     SC_STUB        },
    { 0x0111, "NtReadFileScatter",
      SYS_readv,           "readv",           SC_STUB        },
    { 0x0112, "NtWriteFileGather",
      SYS_writev,          "writev",          SC_STUB        },

    /* ── メモリ管理 ───────────────────────────── */
    { 0x0018, "NtAllocateVirtualMemory",
      SYS_mmap,            "mmap",            SC_TRANSLATED  },
    { 0x001E, "NtFreeVirtualMemory",
      SYS_munmap,          "munmap",          SC_TRANSLATED  },
    { 0x0050, "NtProtectVirtualMemory",
      SYS_mprotect,        "mprotect",        SC_TRANSLATED  },
    { 0x0023, "NtQueryVirtualMemory",
      SC_NO_LINUX,         "(mincore)",       SC_STUB        },
    { 0x002E, "NtFlushVirtualMemory",
      SYS_msync,           "msync",           SC_STUB        },
    { 0x0038, "NtLockVirtualMemory",
      SYS_mlock,           "mlock",           SC_STUB        },
    { 0x0059, "NtUnlockVirtualMemory",
      SYS_munlock,         "munlock",         SC_STUB        },
    { 0x001D, "NtExtendSection",
      SYS_ftruncate,       "ftruncate",       SC_STUB        },
    { 0x004A, "NtCreateSection",
      SYS_mmap,            "mmap",            SC_STUB        },
    { 0x0028, "NtMapViewOfSection",
      SYS_mmap,            "mmap",            SC_STUB        },
    { 0x0049, "NtUnmapViewOfSection",
      SYS_munmap,          "munmap",          SC_STUB        },

    /* ── プロセス・スレッド ───────────────────── */
    { 0x002C, "NtTerminateProcess",
      SYS_exit_group,      "exit_group",      SC_TRANSLATED  },
    { 0x0053, "NtTerminateThread",
      SYS_exit,            "exit",            SC_TRANSLATED  },
    { 0x004E, "NtCreateThread",
      SYS_clone,           "clone",           SC_STUB        },
    { 0x00C8, "NtCreateThreadEx",
      SYS_clone,           "clone",           SC_STUB        },
    { 0x0019, "NtQueryInformationProcess",
      SYS_getpid,         "(procfs)",        SC_TRANSLATED        },
    { 0x0025, "NtQueryInformationThread",
      SC_NO_LINUX,         "(procfs)",        SC_STUB        },
    { 0x000A, "NtSetInformationThread",
      SYS_prctl,           "prctl",           SC_STUB        },
    { 0x002F, "NtSuspendThread",
      SC_NO_LINUX,         "(SIGSTOP)",       SC_STUB        },
    { 0x0032, "NtResumeThread",
      SC_NO_LINUX,         "(SIGCONT)",       SC_STUB        },
    { 0x00F2, "NtGetContextThread",
      SYS_ptrace,          "ptrace",          SC_STUB        },
    { 0x00F5, "NtSetContextThread",
      SYS_ptrace,          "ptrace",          SC_STUB        },
    { 0x001B, "NtOpenProcess",
      SC_NO_LINUX,         "(procfs)",        SC_STUB        },

    /* ── 同期・待機 ───────────────────────────── */
    { 0x0004, "NtWaitForSingleObject",
      SYS_futex,           "futex",           SC_TRANSLATED        },
    { 0x00A0, "NtWaitForMultipleObjects",
      SYS_futex,           "futex",           SC_STUB        },
    { 0x0034, "NtDelayExecution",
      SYS_nanosleep,       "nanosleep",       SC_TRANSLATED  },
    { 0x005A, "NtCreateMutant",
      SYS_futex,         "(futex)",         SC_TRANSLATED        },
    { 0x00B4, "NtReleaseMutant",
      SYS_futex,         "(futex)",         SC_TRANSLATED        },
    { 0x0048, "NtCreateEvent",
      SYS_eventfd2,        "eventfd2",        SC_TRANSLATED        },
    { 0x00D8, "NtSetEvent",
      SYS_write,         "(eventfd write)", SC_TRANSLATED        },
    { 0x00E2, "NtResetEvent",
      SYS_read,         "(eventfd read)",  SC_TRANSLATED        },
    { 0x00BC, "NtCreateSemaphore",
      SC_NO_LINUX,         "(sem_open)",      SC_STUB        },
    { 0x00C3, "NtReleaseSemaphore",
      SC_NO_LINUX,         "(sem_post)",      SC_STUB        },

    /* ── システム情報 ─────────────────────────── */
    { 0x0036, "NtQuerySystemInformation",
      SC_NO_LINUX,         "(sysinfo+proc)",  SC_STUB        },
    { 0x00CE, "NtSetSystemInformation",
      SC_NO_LINUX,         "(sysctl)",        SC_BLOCKED     },
    { 0x0060, "NtQuerySystemTime",
      SYS_clock_gettime,   "clock_gettime",   SC_TRANSLATED        },
    { 0x005E, "NtQueryPerformanceCounter",
      SYS_clock_gettime,   "clock_gettime",   SC_TRANSLATED        },

    /* ── レジストリ ───────────────────────────── */
    { 0x001A, "NtOpenKey",
      SC_NO_LINUX,         "(linexe reg)",    SC_STUB        },
    { 0x005C, "NtCreateKey",
      SC_NO_LINUX,         "(linexe reg)",    SC_STUB        },
    { 0x0017, "NtQueryValueKey",
      SC_NO_LINUX,         "(linexe reg)",    SC_STUB        },
    { 0x00C7, "NtSetValueKey",
      SC_NO_LINUX,         "(linexe reg)",    SC_STUB        },
    { 0x000C, "NtEnumerateKey",
      SC_NO_LINUX,         "(linexe reg)",    SC_STUB        },
    { 0x0010, "NtEnumerateValueKey",
      SC_NO_LINUX,         "(linexe reg)",    SC_STUB        },

    /* ── ソケット（将来対応） ─────────────────── */
    { 0x01A5, "NtCreateIoCompletion",
      SYS_epoll_create1,   "epoll_create1",   SC_STUB        },

    /* 番兵 */
    { 0xFFFF, NULL, SC_NO_LINUX, NULL, SC_UNKNOWN }
};

#define SYSCALL_TABLE_LEN \
    (sizeof(SYSCALL_TABLE) / sizeof(SYSCALL_TABLE[0]) - 1)

/* ════════════════════════════════════════════════
   検索ユーティリティ
   ════════════════════════════════════════════════ */
static inline const SC_ENTRY* sc_find(uint32_t nt_number) {
    for (size_t i = 0; i < SYSCALL_TABLE_LEN; i++) {
        if (SYSCALL_TABLE[i].nt_number == nt_number)
            return &SYSCALL_TABLE[i];
    }
    return NULL;
}

static inline const char* sc_status_str(SC_STATUS s) {
    switch (s) {
        case SC_UNKNOWN:     return "UNKNOWN";
        case SC_STUB:        return "STUB";
        case SC_PASSTHROUGH: return "PASSTHROUGH";
        case SC_TRANSLATED:  return "TRANSLATED";
        case SC_BLOCKED:     return "BLOCKED";
    }
    return "?";
}

#endif /* LINEXE_SYSCALL_TABLE_H */
