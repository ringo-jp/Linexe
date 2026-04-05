/*
 * Linexe - LD_PRELOAD Hook Layer (Phase 2)
 * Licensed under Apache License 2.0
 *
 * BUGFIXES v0.2.1:
 *   - open(): 可変引数からmodeを正しく取得 (O_CREATフラグ対応)
 *   - open(): dlsym初期化をpthread_onceでスレッドセーフ化
 *   - mprotect(): ログ出力をデバッグモード時のみに制限
 *   - VerifyVersionInfoA / IsWow64Process: unused parameter警告を修正
 *   - open64もフックしてLFS環境に対応
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>

#ifndef LINEXE_QUIET
  #define HOOK_LOG(fmt, ...) fprintf(stderr, "[LINEXE] " fmt "\n", ##__VA_ARGS__)
#else
  #define HOOK_LOG(fmt, ...)
#endif

/* mprotectはJIT/ローダーが頻繁に呼ぶため専用フラグで制御 */
#ifdef LINEXE_LOG_MPROTECT
  #define MPROTECT_LOG(fmt, ...) fprintf(stderr, "[LINEXE/MEM] " fmt "\n", ##__VA_ARGS__)
#else
  #define MPROTECT_LOG(fmt, ...)
#endif

typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef int      BOOL;
typedef void*    HANDLE;

/* ════════════════════════════════════════════════
   dlsym キャッシュ（pthread_onceでスレッドセーフ初期化）
   ════════════════════════════════════════════════ */
typedef struct {
    int   (*real_open)(const char*, int, ...);
    int   (*real_open64)(const char*, int, ...);
    int   (*real_mprotect)(void*, size_t, int);
} RealFuncs;

static RealFuncs   g_real   = {0};
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

static void resolve_real_funcs(void) {
    g_real.real_open     = dlsym(RTLD_NEXT, "open");
    g_real.real_open64   = dlsym(RTLD_NEXT, "open64");
    g_real.real_mprotect = dlsym(RTLD_NEXT, "mprotect");
}

static void ensure_init(void) {
    pthread_once(&g_init_once, resolve_real_funcs);
}

/* ════════════════════════════════════════════════
   初期化バナー
   ════════════════════════════════════════════════ */
__attribute__((constructor))
static void linexe_init(void) {
    ensure_init();
    fprintf(stderr,
        "\n"
        "  Linexe Hook Layer v0.2.1 - Active\n"
        "  Spoofing: Windows 10 Pro 22H2 (19045)\n\n");
}

/* ════════════════════════════════════════════════
   カテゴリA：OS識別 API
   ════════════════════════════════════════════════ */
typedef struct {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    char  szCSDVersion[128];
} OSVERSIONINFOA;

typedef struct {
    DWORD   dwOSVersionInfoSize;
    DWORD   dwMajorVersion;
    DWORD   dwMinorVersion;
    DWORD   dwBuildNumber;
    DWORD   dwPlatformId;
    char    szCSDVersion[128];
    WORD    wServicePackMajor;
    WORD    wServicePackMinor;
    WORD    wSuiteMask;
    uint8_t wProductType;
    uint8_t wReserved;
} OSVERSIONINFOEXA;

BOOL GetVersionExA(OSVERSIONINFOA* lpVersionInfo) {
    if (!lpVersionInfo) return 0;
    lpVersionInfo->dwMajorVersion = 10;
    lpVersionInfo->dwMinorVersion = 0;
    lpVersionInfo->dwBuildNumber  = 19045;
    lpVersionInfo->dwPlatformId   = 2;
    memset(lpVersionInfo->szCSDVersion, 0, 128);
    HOOK_LOG("GetVersionExA -> Windows 10.0.19045");
    return 1;
}

BOOL GetVersionExW(void* lpVersionInfo) {
    return GetVersionExA((OSVERSIONINFOA*)lpVersionInfo);
}

uint32_t RtlGetVersion(OSVERSIONINFOEXA* lpVersionInfo) {
    if (!lpVersionInfo) return 0xC0000005;
    lpVersionInfo->dwMajorVersion    = 10;
    lpVersionInfo->dwMinorVersion    = 0;
    lpVersionInfo->dwBuildNumber     = 19045;
    lpVersionInfo->dwPlatformId      = 2;
    lpVersionInfo->wServicePackMajor = 0;
    lpVersionInfo->wServicePackMinor = 0;
    lpVersionInfo->wProductType      = 1;
    HOOK_LOG("RtlGetVersion -> Windows 10.0.19045");
    return 0;
}

/* BUG FIX: 未使用パラメータをvoidキャストで明示的に無視 */
BOOL VerifyVersionInfoA(void* lpVersionInfo, DWORD dwTypeMask,
                         uint64_t dwlConditionMask) {
    (void)lpVersionInfo;
    (void)dwTypeMask;
    (void)dwlConditionMask;
    HOOK_LOG("VerifyVersionInfoA -> forced TRUE");
    return 1;
}

BOOL IsWow64Process(HANDLE hProcess, BOOL* Wow64Process) {
    (void)hProcess;
    if (Wow64Process) *Wow64Process = 0;
    HOOK_LOG("IsWow64Process -> FALSE (native x64)");
    return 1;
}

typedef struct {
    WORD    wProcessorArchitecture;
    WORD    wReserved;
    DWORD   dwPageSize;
    void*   lpMinimumApplicationAddress;
    void*   lpMaximumApplicationAddress;
    uint64_t dwActiveProcessorMask;
    DWORD   dwNumberOfProcessors;
    DWORD   dwProcessorType;
    DWORD   dwAllocationGranularity;
    WORD    wProcessorLevel;
    WORD    wProcessorRevision;
} SYSTEM_INFO;

void GetSystemInfo(SYSTEM_INFO* lpSystemInfo) {
    if (!lpSystemInfo) return;
    memset(lpSystemInfo, 0, sizeof(*lpSystemInfo));
    lpSystemInfo->wProcessorArchitecture      = 9;
    lpSystemInfo->dwPageSize                  = 4096;
    lpSystemInfo->lpMinimumApplicationAddress = (void*)0x10000;
    lpSystemInfo->lpMaximumApplicationAddress = (void*)0x7FFFFFFEFFFF;
    lpSystemInfo->dwActiveProcessorMask       = 0xF;
    lpSystemInfo->dwNumberOfProcessors        = 4;
    lpSystemInfo->dwAllocationGranularity     = 65536;
    lpSystemInfo->wProcessorLevel             = 6;
    HOOK_LOG("GetSystemInfo -> x64, 4 cores");
}

/* ════════════════════════════════════════════════
   カテゴリB：ファイルシステム
   ════════════════════════════════════════════════ */

/* Windowsパス判定：C:\... または \... 形式 */
static int is_windows_path(const char* path) {
    if (!path || path[0] == '\0') return 0;
    /* BUG FIX v0.2.2: 空文字列で path[1] を読むと範囲外アクセス */
    size_t len = strlen(path);
    if (len >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) return 1;
    if (len >= 2 && path[0] == '\\' && path[1] == '\\') return 1; /* UNCパス */
    return 0;
}

static void win_to_linux_path(const char* wpath, char* out, size_t outsz) {
    if (!wpath) { out[0] = '\0'; return; }

    if (!is_windows_path(wpath)) {
        strncpy(out, wpath, outsz - 1);
        out[outsz - 1] = '\0';
        return;
    }

    const char* home = getenv("HOME");
    if (!home) home = "/tmp";

    if (strncasecmp(wpath, "C:\\Users\\", 9) == 0) {
        snprintf(out, outsz, "%s/%s", home, wpath + 9);
    } else if (strncasecmp(wpath, "C:\\Windows", 10) == 0) {
        snprintf(out, outsz, "/tmp/linexe_windows%s", wpath + 10);
    } else if (wpath[1] == ':') {
        snprintf(out, outsz, "%s/linexe_c/%s", home, wpath + 3);
    } else {
        strncpy(out, wpath, outsz - 1);
        out[outsz - 1] = '\0';
    }

    for (char* p = out; *p; p++) if (*p == '\\') *p = '/';
    HOOK_LOG("path: \"%s\" -> \"%s\"", wpath, out);
}

/*
 * BUG FIX: open() の mode 引数を可変引数から正しく取得する。
 * O_CREAT または O_TMPFILE が指定された場合のみ mode を読む。
 * 以前のコードは常に 0644 を渡しており、
 * カスタムパーミッションでのファイル作成が壊れていた。
 */
int open(const char* pathname, int flags, ...) {
    ensure_init();

    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    char linpath[4096];
    win_to_linux_path(pathname, linpath, sizeof(linpath));
    return g_real.real_open(linpath, flags, mode);
}

/* BUG FIX: open64もフックしてLFS(_FILE_OFFSET_BITS=64)環境に対応 */
int open64(const char* pathname, int flags, ...) {
    ensure_init();

    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    char linpath[4096];
    win_to_linux_path(pathname, linpath, sizeof(linpath));

    if (g_real.real_open64)
        return g_real.real_open64(linpath, flags, mode);
    return g_real.real_open(linpath, flags, mode);
}

/* ════════════════════════════════════════════════
   カテゴリC：メモリ管理
   BUG FIX: mprotectログをLINEXE_LOG_MPROTECT時のみ出力。
   JIT/ローダーが毎フレーム呼ぶためデフォルトはサイレント。
   ════════════════════════════════════════════════ */
int mprotect(void* addr, size_t len, int prot) {
    ensure_init();
    MPROTECT_LOG("mprotect(%p, %zu, prot=0x%x)", addr, len, prot);
    return g_real.real_mprotect(addr, len, prot);
}
