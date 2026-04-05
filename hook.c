/*
 * Linexe - LD_PRELOAD Hook Layer (Phase 2 - フック機構)
 * Licensed under Apache License 2.0
 *
 * 使い方:
 *   gcc -shared -fPIC -o linexe_hook.so src/hook.c -ldl
 *   LD_PRELOAD=./linexe_hook.so wine ./target.exe
 *
 * 仕組み:
 *   EXEが呼び出すlibc/Wine関数をこのsoが横取りし、
 *   「Windows 10だよ」と嘘をつく。
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>      /* dlsym, RTLD_NEXT */
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

/* ログ出力マクロ（リリース時は -DLINEXE_QUIET でオフ） */
#ifndef LINEXE_QUIET
  #define HOOK_LOG(fmt, ...) fprintf(stderr, "[LINEXE] " fmt "\n", ##__VA_ARGS__)
#else
  #define HOOK_LOG(fmt, ...)
#endif

/* ════════════════════════════════════════════════
   Windows型 最小定義
   ════════════════════════════════════════════════ */
typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef int      BOOL;
typedef void*    HANDLE;
typedef char*    LPSTR;

typedef struct {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    char  szCSDVersion[128];
} OSVERSIONINFOA;

typedef struct {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    char  szCSDVersion[128];
    WORD  wServicePackMajor;
    WORD  wServicePackMinor;
    WORD  wSuiteMask;
    uint8_t wProductType;
    uint8_t wReserved;
} OSVERSIONINFOEXA;

/* ════════════════════════════════════════════════
   初期化：ライブラリロード時に実行される
   ════════════════════════════════════════════════ */
__attribute__((constructor))
static void linexe_init(void) {
    fprintf(stderr,
        "\n╔══════════════════════════════════════╗\n"
        "║  Linexe Hook Layer - Active          ║\n"
        "║  Target: Windows 10.0.19045 spoof    ║\n"
        "╚══════════════════════════════════════╝\n\n");
}

/* ════════════════════════════════════════════════
   カテゴリA：OS識別 フック
   ════════════════════════════════════════════════ */

/* GetVersionExA のフック */
BOOL GetVersionExA(OSVERSIONINFOA* lpVersionInfo) {
    if (!lpVersionInfo) return 0;
    lpVersionInfo->dwMajorVersion = 10;
    lpVersionInfo->dwMinorVersion = 0;
    lpVersionInfo->dwBuildNumber  = 19045;
    lpVersionInfo->dwPlatformId   = 2;
    memset(lpVersionInfo->szCSDVersion, 0, 128);
    HOOK_LOG("GetVersionExA -> spoofed Windows 10.0.19045");
    return 1;
}

/* GetVersionExW のフック（ワイド文字版） */
BOOL GetVersionExW(void* lpVersionInfo) {
    /* ワイド版は構造体レイアウトが同じなのでキャスト流用 */
    return GetVersionExA((OSVERSIONINFOA*)lpVersionInfo);
}

/* RtlGetVersion のフック（ntdll.dll 経由の検出対策） */
uint32_t RtlGetVersion(OSVERSIONINFOEXA* lpVersionInfo) {
    if (!lpVersionInfo) return 0xC0000005; /* STATUS_ACCESS_VIOLATION */
    lpVersionInfo->dwMajorVersion    = 10;
    lpVersionInfo->dwMinorVersion    = 0;
    lpVersionInfo->dwBuildNumber     = 19045;
    lpVersionInfo->dwPlatformId      = 2;
    lpVersionInfo->wServicePackMajor = 0;
    lpVersionInfo->wServicePackMinor = 0;
    lpVersionInfo->wProductType      = 1; /* VER_NT_WORKSTATION */
    HOOK_LOG("RtlGetVersion -> spoofed Windows 10.0.19045");
    return 0; /* STATUS_SUCCESS */
}

/* VerifyVersionInfoA のフック → 常にTRUE（バージョン確認を無効化） */
BOOL VerifyVersionInfoA(void* lpVersionInfo, DWORD dwTypeMask, uint64_t dwlConditionMask) {
    HOOK_LOG("VerifyVersionInfoA -> forced TRUE");
    return 1;
}

/* IsWow64Process のフック → FALSE（64bitネイティブのふり） */
BOOL IsWow64Process(HANDLE hProcess, BOOL* Wow64Process) {
    if (Wow64Process) *Wow64Process = 0;
    HOOK_LOG("IsWow64Process -> FALSE (native x64)");
    return 1;
}

/* GetSystemInfo のフック → x64システムとして偽装 */
typedef struct {
    WORD  wProcessorArchitecture; /* 9 = PROCESSOR_ARCHITECTURE_AMD64 */
    WORD  wReserved;
    DWORD dwPageSize;
    void* lpMinimumApplicationAddress;
    void* lpMaximumApplicationAddress;
    uint64_t dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD  wProcessorLevel;
    WORD  wProcessorRevision;
} SYSTEM_INFO;

void GetSystemInfo(SYSTEM_INFO* lpSystemInfo) {
    if (!lpSystemInfo) return;
    memset(lpSystemInfo, 0, sizeof(*lpSystemInfo));
    lpSystemInfo->wProcessorArchitecture    = 9;    /* AMD64 */
    lpSystemInfo->dwPageSize                = 4096;
    lpSystemInfo->lpMinimumApplicationAddress = (void*)0x10000;
    lpSystemInfo->lpMaximumApplicationAddress = (void*)0x7FFFFFFEFFFF;
    lpSystemInfo->dwActiveProcessorMask     = (uint64_t)((1 << 4) - 1);
    lpSystemInfo->dwNumberOfProcessors      = 4;
    lpSystemInfo->dwAllocationGranularity   = 65536;
    lpSystemInfo->wProcessorLevel           = 6;
    HOOK_LOG("GetSystemInfo -> x64, 4 cores, 4KB pages");
}

/* ════════════════════════════════════════════════
   カテゴリB：ファイルシステム フック
   Windowsパスを透過的にLinuxパスに変換
   ════════════════════════════════════════════════ */

/* Windowsパス → Linuxパス変換
 * C:\Users\foo → /home/$USER/foo
 * C:\Windows   → /tmp/linexe_windows（仮想フォルダ） */
static void win_to_linux_path(const char* wpath, char* out, size_t outsz) {
    if (!wpath) { out[0] = '\0'; return; }

    /* すでにLinuxパスなら何もしない */
    if (wpath[0] == '/') {
        strncpy(out, wpath, outsz - 1);
        out[outsz - 1] = '\0';
        return;
    }

    const char* home = getenv("HOME");
    if (!home) home = "/tmp";

    /* C:\Users\xxx → /home/... */
    if (strncasecmp(wpath, "C:\\Users\\", 9) == 0) {
        snprintf(out, outsz, "%s/%s", home, wpath + 9);
    }
    /* C:\Windows → 仮想Windowsフォルダ */
    else if (strncasecmp(wpath, "C:\\Windows", 10) == 0) {
        snprintf(out, outsz, "/tmp/linexe_windows%s", wpath + 10);
    }
    /* C:\ 一般 → $HOME/linexe_c/ */
    else if (wpath[1] == ':' && (wpath[2] == '\\' || wpath[2] == '/')) {
        snprintf(out, outsz, "%s/linexe_c/%s", home, wpath + 3);
    }
    else {
        strncpy(out, wpath, outsz - 1);
        out[outsz - 1] = '\0';
    }

    /* バックスラッシュ → スラッシュ */
    for (char* p = out; *p; p++) if (*p == '\\') *p = '/';

    HOOK_LOG("path: \"%s\" -> \"%s\"", wpath, out);
}

/* openのフック（パス変換付き） */
int open(const char* pathname, int flags, ...) {
    static int (*real_open)(const char*, int, ...) = NULL;
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");

    char linpath[4096];
    win_to_linux_path(pathname, linpath, sizeof(linpath));
    return real_open(linpath, flags, 0644);
}

/* ════════════════════════════════════════════════
   カテゴリC：メモリ管理 フック
   VirtualAlloc/Free は mmap/munmap に変換済みなので
   ここではmprotect をラップしてログを追加
   ════════════════════════════════════════════════ */

int mprotect(void* addr, size_t len, int prot) {
    static int (*real_mprotect)(void*, size_t, int) = NULL;
    if (!real_mprotect) real_mprotect = dlsym(RTLD_NEXT, "mprotect");

    HOOK_LOG("mprotect(%p, %zu, prot=%d)", addr, len, prot);
    return real_mprotect(addr, len, prot);
}
