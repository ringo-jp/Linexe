/*
 * Linexe - Virtual Registry Hook (Phase 2)
 * Licensed under Apache License 2.0
 *
 * WindowsレジストリAPIを横取りし、
 * インメモリの偽レジストリから値を返す。
 *
 * 対応API:
 *   RegOpenKeyExA / RegOpenKeyExW
 *   RegQueryValueExA / RegQueryValueExW
 *   RegCloseKey
 *   RegGetValueA
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef LINEXE_QUIET
  #define HOOK_LOG(fmt, ...) fprintf(stderr, "[LINEXE/REG] " fmt "\n", ##__VA_ARGS__)
#else
  #define HOOK_LOG(fmt, ...)
#endif

/* ════════════════════════════════════════════════
   型定義
   ════════════════════════════════════════════════ */
typedef uint32_t DWORD;
typedef void*    HKEY;
typedef int      LONG;

#define REG_NONE        0
#define REG_SZ          1
#define REG_DWORD       4
#define ERROR_SUCCESS   0
#define ERROR_NOT_FOUND 2

/* 仮想HKEYマジック値（NULLと区別するため） */
#define FAKE_HKEY_BASE  0xFEED0000UL

/* ════════════════════════════════════════════════
   仮想レジストリ定義
   Windows 10 Pro に見せかけるための最小セット
   ════════════════════════════════════════════════ */
typedef struct {
    const char* key_path;
    const char* value_name;
    uint32_t    type;       /* REG_SZ or REG_DWORD */
    const char* str_data;   /* REG_SZ用 */
    uint32_t    dword_data; /* REG_DWORD用 */
} REG_ENTRY;

static const REG_ENTRY FAKE_REGISTRY[] = {
    /* OS バージョン情報 */
    { "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      "CurrentBuildNumber",    REG_SZ,    "19045",          0 },
    { "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      "CurrentVersion",        REG_SZ,    "10.0",           0 },
    { "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      "ProductName",           REG_SZ,    "Windows 10 Pro", 0 },
    { "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      "EditionID",             REG_SZ,    "Professional",   0 },
    { "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      "ReleaseId",             REG_SZ,    "22H2",           0 },
    { "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      "UBR",                   REG_DWORD, NULL,             3803 },

    /* システム情報 */
    { "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
      "PROCESSOR_ARCHITECTURE", REG_SZ,  "AMD64",          0 },
    { "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
      "NUMBER_OF_PROCESSORS",   REG_SZ,  "4",              0 },
    { "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
      "OS",                     REG_SZ,  "Windows_NT",     0 },

    /* DirectX / GPU（Phase 4対応の準備） */
    { "HKLM\\SOFTWARE\\Microsoft\\DirectX",
      "Version",               REG_SZ,    "4.09.00.0904",  0 },

    /* 番兵 */
    { NULL, NULL, 0, NULL, 0 }
};

/* ════════════════════════════════════════════════
   仮想HKEYテーブル
   RegOpenKeyExが返す偽ハンドルを管理する
   ════════════════════════════════════════════════ */
#define MAX_FAKE_HKEYS 64

typedef struct {
    int         in_use;
    char        key_path[512];
    uintptr_t   handle_val;
} FAKE_HKEY_ENTRY;

static FAKE_HKEY_ENTRY hkey_table[MAX_FAKE_HKEYS];
static uintptr_t       hkey_counter = FAKE_HKEY_BASE;

static HKEY alloc_fake_hkey(const char* path) {
    for (int i = 0; i < MAX_FAKE_HKEYS; i++) {
        if (!hkey_table[i].in_use) {
            hkey_table[i].in_use = 1;
            strncpy(hkey_table[i].key_path, path,
                    sizeof(hkey_table[i].key_path) - 1);
            hkey_table[i].handle_val = hkey_counter++;
            return (HKEY)(uintptr_t)hkey_table[i].handle_val;
        }
    }
    return NULL;
}

static const char* resolve_hkey_path(HKEY hKey) {
    uintptr_t val = (uintptr_t)hKey;
    for (int i = 0; i < MAX_FAKE_HKEYS; i++) {
        if (hkey_table[i].in_use &&
            hkey_table[i].handle_val == val) {
            return hkey_table[i].key_path;
        }
    }
    /* 定義済みルートキーを文字列に変換 */
    if (val == 0x80000001) return "HKCU";
    if (val == 0x80000002) return "HKLM";
    if (val == 0x80000005) return "HKLM\\SOFTWARE";
    return "UNKNOWN";
}

static void free_fake_hkey(HKEY hKey) {
    uintptr_t val = (uintptr_t)hKey;
    for (int i = 0; i < MAX_FAKE_HKEYS; i++) {
        if (hkey_table[i].in_use &&
            hkey_table[i].handle_val == val) {
            hkey_table[i].in_use = 0;
            return;
        }
    }
}

/* ════════════════════════════════════════════════
   レジストリ検索
   ════════════════════════════════════════════════ */
static const REG_ENTRY* reg_find(const char* full_path,
                                  const char* value_name) {
    for (int i = 0; FAKE_REGISTRY[i].key_path != NULL; i++) {
        if (strcasecmp(FAKE_REGISTRY[i].key_path, full_path) == 0 &&
            strcasecmp(FAKE_REGISTRY[i].value_name, value_name) == 0) {
            return &FAKE_REGISTRY[i];
        }
    }
    return NULL;
}

/* ════════════════════════════════════════════════
   RegOpenKeyExA フック
   ════════════════════════════════════════════════ */
LONG RegOpenKeyExA(HKEY hKey, const char* lpSubKey,
                   DWORD ulOptions, DWORD samDesired,
                   HKEY* phkResult)
{
    (void)ulOptions; (void)samDesired;

    char full_path[512];
    const char* base = resolve_hkey_path(hKey);

    if (lpSubKey && lpSubKey[0]) {
        snprintf(full_path, sizeof(full_path), "%s\\%s", base, lpSubKey);
    } else {
        strncpy(full_path, base, sizeof(full_path) - 1);
    }

    if (phkResult) {
        *phkResult = alloc_fake_hkey(full_path);
        HOOK_LOG("RegOpenKeyExA(\"%s\") -> handle %p",
                 full_path, *phkResult);
        return ERROR_SUCCESS;
    }
    return ERROR_NOT_FOUND;
}

/* ════════════════════════════════════════════════
   RegQueryValueExA フック
   ════════════════════════════════════════════════ */
LONG RegQueryValueExA(HKEY hKey, const char* lpValueName,
                      DWORD* lpReserved, DWORD* lpType,
                      void* lpData, DWORD* lpcbData)
{
    (void)lpReserved;

    const char* key_path = resolve_hkey_path(hKey);
    const REG_ENTRY* entry = reg_find(key_path, lpValueName);

    if (!entry) {
        HOOK_LOG("RegQueryValueExA(\"%s\" -> \"%s\") -> NOT FOUND",
                 key_path, lpValueName);
        return ERROR_NOT_FOUND;
    }

    if (entry->type == REG_SZ) {
        size_t len = strlen(entry->str_data) + 1;
        if (lpType)    *lpType = REG_SZ;
        if (lpData && lpcbData && *lpcbData >= (DWORD)len)
            memcpy(lpData, entry->str_data, len);
        if (lpcbData)  *lpcbData = (DWORD)len;
        HOOK_LOG("RegQueryValueExA(\"%s\") -> \"%s\"",
                 lpValueName, entry->str_data);

    } else if (entry->type == REG_DWORD) {
        if (lpType)    *lpType = REG_DWORD;
        if (lpData && lpcbData && *lpcbData >= 4)
            memcpy(lpData, &entry->dword_data, 4);
        if (lpcbData)  *lpcbData = 4;
        HOOK_LOG("RegQueryValueExA(\"%s\") -> %u",
                 lpValueName, entry->dword_data);
    }

    return ERROR_SUCCESS;
}

/* ════════════════════════════════════════════════
   RegCloseKey フック
   ════════════════════════════════════════════════ */
LONG RegCloseKey(HKEY hKey) {
    HOOK_LOG("RegCloseKey(%p)", hKey);
    free_fake_hkey(hKey);
    return ERROR_SUCCESS;
}

/* ════════════════════════════════════════════════
   RegGetValueA フック（Vista以降のモダンAPI）
   ════════════════════════════════════════════════ */
LONG RegGetValueA(HKEY hKey, const char* lpSubKey,
                  const char* lpValue, DWORD dwFlags,
                  DWORD* pdwType, void* pvData, DWORD* pcbData)
{
    (void)dwFlags;

    /* パスを組み立ててRegQueryValueExAに委譲 */
    HKEY sub = NULL;
    if (lpSubKey && lpSubKey[0]) {
        RegOpenKeyExA(hKey, lpSubKey, 0, 0, &sub);
    } else {
        sub = hKey;
    }

    LONG result = RegQueryValueExA(sub, lpValue, NULL,
                                   pdwType, pvData, pcbData);
    if (lpSubKey && lpSubKey[0] && sub) RegCloseKey(sub);
    return result;
}

/* ════════════════════════════════════════════════
   セルフテスト
   ════════════════════════════════════════════════ */
#ifdef LINEXE_TEST_REGISTRY
int main(void) {
    printf("=== Linexe Virtual Registry - Self Test ===\n\n");

    HKEY hk = NULL;
    LONG r = RegOpenKeyExA(
        (HKEY)0x80000002, /* HKLM */
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, 0, &hk);
    printf("RegOpenKeyExA -> %s (handle=%p)\n\n",
           r == 0 ? "OK" : "FAIL", hk);

    char buf[64];
    DWORD sz = sizeof(buf), type = 0;

    sz = sizeof(buf);
    RegQueryValueExA(hk, "ProductName", NULL, &type, buf, &sz);
    printf("ProductName  = \"%s\" (type=%u)\n", buf, type);

    sz = sizeof(buf);
    RegQueryValueExA(hk, "CurrentVersion", NULL, &type, buf, &sz);
    printf("CurrentVersion = \"%s\"\n", buf);

    sz = sizeof(buf);
    RegQueryValueExA(hk, "ReleaseId", NULL, &type, buf, &sz);
    printf("ReleaseId    = \"%s\"\n", buf);

    DWORD ubr = 0; sz = 4;
    RegQueryValueExA(hk, "UBR", NULL, &type, &ubr, &sz);
    printf("UBR          = %u (REG_DWORD)\n\n", ubr);

    RegCloseKey(hk);
    printf("[+] Registry test done.\n");
    return 0;
}
#endif
