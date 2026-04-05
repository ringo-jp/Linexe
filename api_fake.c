/*
 * Linexe - Windows API Fake Layer (Phase 2)
 * Licensed under Apache License 2.0
 *
 * 役割：EXEが「俺はWindowsか？」と聞いてきたとき
 *       「はい、Windows 10です！」と答えるレイヤー。
 *
 * 実装方針：LD_PRELOADまたはPLTフックで
 *           偽のDLL関数を差し込む。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ════════════════════════════════════════════════
   カテゴリA：OS識別系 API
   EXEが「Windowsか確認」する関数を偽装する
   ════════════════════════════════════════════════ */

typedef struct {
    uint32_t dwOSVersionInfoSize;
    uint32_t dwMajorVersion;
    uint32_t dwMinorVersion;
    uint32_t dwBuildNumber;
    uint32_t dwPlatformId;
    char     szCSDVersion[128];
} OSVERSIONINFOA;

typedef struct {
    uint32_t dwOSVersionInfoSize;
    uint32_t dwMajorVersion;
    uint32_t dwMinorVersion;
    uint32_t dwBuildNumber;
    uint32_t dwPlatformId;
    char     szCSDVersion[128];
    uint16_t wServicePackMajor;
    uint16_t wServicePackMinor;
    uint16_t wSuiteMask;
    uint8_t  wProductType;
    uint8_t  wReserved;
} OSVERSIONINFOEXA;

/* GetVersionExA の偽実装
 * → 常に Windows 10 Pro (Build 19045) を返す */
int fake_GetVersionExA(OSVERSIONINFOA* lpVersionInfo) {
    if (!lpVersionInfo) return 0;
    lpVersionInfo->dwMajorVersion = 10;
    lpVersionInfo->dwMinorVersion = 0;
    lpVersionInfo->dwBuildNumber  = 19045;
    lpVersionInfo->dwPlatformId   = 2; /* VER_PLATFORM_WIN32_NT */
    strncpy(lpVersionInfo->szCSDVersion, "", 128);
    printf("[API_FAKE] GetVersionExA -> Windows 10.0.19045\n");
    return 1; /* TRUE */
}

/* RtlGetVersion の偽実装（より低レベル・検出されにくい）
 * GetVersionExより信頼されるAPI */
int fake_RtlGetVersion(OSVERSIONINFOEXA* lpVersionInfo) {
    if (!lpVersionInfo) return 0;
    lpVersionInfo->dwMajorVersion    = 10;
    lpVersionInfo->dwMinorVersion    = 0;
    lpVersionInfo->dwBuildNumber     = 19045;
    lpVersionInfo->dwPlatformId      = 2;
    lpVersionInfo->wServicePackMajor = 0;
    lpVersionInfo->wServicePackMinor = 0;
    lpVersionInfo->wProductType      = 1; /* VER_NT_WORKSTATION */
    printf("[API_FAKE] RtlGetVersion -> Windows 10.0.19045\n");
    return 0; /* STATUS_SUCCESS */
}

/* IsWow64Process の偽実装
 * → FALSE = 64bitネイティブとして動いているふり */
int fake_IsWow64Process(void* hProcess, int* Wow64Process) {
    if (Wow64Process) *Wow64Process = 0; /* FALSE */
    printf("[API_FAKE] IsWow64Process -> FALSE (native 64bit)\n");
    return 1; /* TRUE = 成功 */
}


/* ════════════════════════════════════════════════
   カテゴリB：ファイルシステム系 API
   Windows I/O → POSIX に変換
   ════════════════════════════════════════════════ */

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* CreateFileA の偽実装 → open() に変換 */
int fake_CreateFileA(const char* lpFileName,
                     uint32_t    dwDesiredAccess,
                     uint32_t    dwShareMode,
                     void*       lpSecurityAttributes,
                     uint32_t    dwCreationDisposition,
                     uint32_t    dwFlagsAndAttributes,
                     void*       hTemplateFile)
{
    int flags = 0;

    /* GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000 */
    int r = (dwDesiredAccess & 0x80000000) != 0;
    int w = (dwDesiredAccess & 0x40000000) != 0;
    if (r && w) flags = O_RDWR;
    else if (w) flags = O_WRONLY;
    else        flags = O_RDONLY;

    /* CreationDisposition の変換
     * CREATE_ALWAYS=2, OPEN_EXISTING=3, CREATE_NEW=1 等 */
    switch (dwCreationDisposition) {
        case 1: flags |= O_CREAT | O_EXCL;    break; /* CREATE_NEW */
        case 2: flags |= O_CREAT | O_TRUNC;   break; /* CREATE_ALWAYS */
        case 3: /* OPEN_EXISTING: そのまま */  break;
        case 4: flags |= O_CREAT;             break; /* OPEN_ALWAYS */
        case 5: flags |= O_TRUNC;             break; /* TRUNCATE_EXISTING */
    }

    int fd = open(lpFileName, flags, 0644);
    printf("[API_FAKE] CreateFileA(\"%s\") -> fd=%d\n", lpFileName, fd);
    return (fd < 0) ? -1 /* INVALID_HANDLE_VALUE */ : fd;
}

/* ReadFile の偽実装 → read() に変換 */
int fake_ReadFile(int     hFile,
                  void*   lpBuffer,
                  uint32_t nNumberOfBytesToRead,
                  uint32_t* lpNumberOfBytesRead,
                  void*   lpOverlapped)
{
    ssize_t n = read(hFile, lpBuffer, nNumberOfBytesToRead);
    if (lpNumberOfBytesRead) *lpNumberOfBytesRead = (n > 0) ? (uint32_t)n : 0;
    printf("[API_FAKE] ReadFile(fd=%d, size=%u) -> %zd bytes\n",
           hFile, nNumberOfBytesToRead, n);
    return (n >= 0) ? 1 : 0;
}

/* WriteFile の偽実装 → write() に変換 */
int fake_WriteFile(int      hFile,
                   const void* lpBuffer,
                   uint32_t nNumberOfBytesToWrite,
                   uint32_t* lpNumberOfBytesWritten,
                   void*    lpOverlapped)
{
    ssize_t n = write(hFile, lpBuffer, nNumberOfBytesToWrite);
    if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = (n > 0) ? (uint32_t)n : 0;
    printf("[API_FAKE] WriteFile(fd=%d, size=%u) -> %zd bytes\n",
           hFile, nNumberOfBytesToWrite, n);
    return (n >= 0) ? 1 : 0;
}


/* ════════════════════════════════════════════════
   カテゴリC：メモリ管理系 API
   VirtualAlloc/Free → mmap/munmap に変換
   ════════════════════════════════════════════════ */

#include <sys/mman.h>

#define MEM_COMMIT   0x1000
#define MEM_RESERVE  0x2000
#define PAGE_READWRITE     0x04
#define PAGE_EXECUTE_READ  0x20
#define PAGE_EXECUTE_READWRITE 0x40

/* VirtualAlloc → mmap */
void* fake_VirtualAlloc(void*    lpAddress,
                         size_t   dwSize,
                         uint32_t flAllocationType,
                         uint32_t flProtect)
{
    int prot = PROT_NONE;
    if (flProtect & PAGE_READWRITE)         prot = PROT_READ | PROT_WRITE;
    if (flProtect & PAGE_EXECUTE_READ)      prot = PROT_READ | PROT_EXEC;
    if (flProtect & PAGE_EXECUTE_READWRITE) prot = PROT_READ | PROT_WRITE | PROT_EXEC;

    int mflags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (lpAddress) mflags |= MAP_FIXED_NOREPLACE;

    void* ptr = mmap(lpAddress, dwSize, prot, mflags, -1, 0);
    if (ptr == MAP_FAILED) ptr = NULL;
    printf("[API_FAKE] VirtualAlloc(size=%zu) -> %p\n", dwSize, ptr);
    return ptr;
}

/* VirtualFree → munmap */
int fake_VirtualFree(void* lpAddress, size_t dwSize, uint32_t dwFreeType) {
    int r = munmap(lpAddress, dwSize);
    printf("[API_FAKE] VirtualFree(%p) -> %s\n", lpAddress, r == 0 ? "OK" : "FAIL");
    return (r == 0) ? 1 : 0;
}


/* ════════════════════════════════════════════════
   仮想レジストリ（最小実装）
   ════════════════════════════════════════════════ */

typedef struct {
    const char* key;
    const char* value_name;
    const char* data;
} REG_ENTRY;

/* Windows 10 に見せかけるためのレジストリ偽データ */
static const REG_ENTRY FAKE_REGISTRY[] = {
    {
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "CurrentBuildNumber", "19045"
    },
    {
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "CurrentVersion", "10.0"
    },
    {
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "ProductName", "Windows 10 Pro"
    },
    {
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "EditionID", "Professional"
    },
    { NULL, NULL, NULL }
};

/* RegQueryValueExA の偽実装 */
int fake_RegQueryValueExA(const char* hKey,
                           const char* lpValueName,
                           uint32_t*   lpReserved,
                           uint32_t*   lpType,
                           void*       lpData,
                           uint32_t*   lpcbData)
{
    for (int i = 0; FAKE_REGISTRY[i].key != NULL; i++) {
        if (strcmp(FAKE_REGISTRY[i].value_name, lpValueName) == 0) {
            const char* data = FAKE_REGISTRY[i].data;
            size_t len = strlen(data) + 1;
            if (lpData && lpcbData && *lpcbData >= len) {
                memcpy(lpData, data, len);
            }
            if (lpcbData) *lpcbData = (uint32_t)len;
            if (lpType)   *lpType   = 1; /* REG_SZ */
            printf("[API_FAKE] RegQueryValueExA(\"%s\") -> \"%s\"\n",
                   lpValueName, data);
            return 0; /* ERROR_SUCCESS */
        }
    }
    printf("[API_FAKE] RegQueryValueExA(\"%s\") -> NOT FOUND\n", lpValueName);
    return 2; /* ERROR_FILE_NOT_FOUND */
}


/* ════════════════════════════════════════════════
   テスト用エントリポイント
   ════════════════════════════════════════════════ */
#ifdef LINEXE_TEST_API
int main(void) {
    printf("=== Linexe API Fake Layer - Self Test ===\n\n");

    /* OS偽装テスト */
    OSVERSIONINFOA ovi = { .dwOSVersionInfoSize = sizeof(OSVERSIONINFOA) };
    fake_GetVersionExA(&ovi);
    printf("    -> Major=%u Minor=%u Build=%u\n\n",
           ovi.dwMajorVersion, ovi.dwMinorVersion, ovi.dwBuildNumber);

    /* IsWow64テスト */
    int wow = -1;
    fake_IsWow64Process((void*)1, &wow);
    printf("    -> WoW64=%d\n\n", wow);

    /* メモリ割り当てテスト */
    void* mem = fake_VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    printf("    -> mem=%p\n", mem);
    if (mem) fake_VirtualFree(mem, 4096, 0);

    /* レジストリテスト */
    char buf[64];
    uint32_t sz = sizeof(buf);
    fake_RegQueryValueExA(NULL, "ProductName", NULL, NULL, buf, &sz);
    printf("    -> ProductName=\"%s\"\n\n", buf);

    printf("[+] All tests done.\n");
    return 0;
}
#endif
