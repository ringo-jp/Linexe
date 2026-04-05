/*
 * Linexe - Virtual Registry Hook Layer (patched draft)
 * Minimal safety pass: null termination + mutex around fake handle table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

typedef uint32_t DWORD;
typedef int32_t  LONG;
typedef uint8_t  BYTE;
typedef BYTE*    LPBYTE;
typedef char*    LPSTR;
typedef const char* LPCSTR;
typedef DWORD*   LPDWORD;
typedef void*    HKEY;

#define ERROR_SUCCESS 0
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_MORE_DATA 234
#define ERROR_INVALID_HANDLE 6
#define ERROR_NOT_ENOUGH_MEMORY 8

#define REG_SZ 1
#define MAX_FAKE_HKEYS 128
#define MAX_KEY_PATH   256

typedef struct {
    int used;
    char key_path[MAX_KEY_PATH];
} FakeHKeyEntry;

static FakeHKeyEntry hkey_table[MAX_FAKE_HKEYS];
static int hkey_counter = 0;
static pthread_mutex_t g_hkey_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    const char *name;
    const char *value;
} FakeRegValue;

static const FakeRegValue g_values[] = {
    { "ProductName", "Windows 10 Pro" },
    { "CurrentBuild", "19045" },
    { "CurrentVersion", "10.0" },
    { "EditionID", "Professional" },
    { NULL, NULL }
};

static HKEY alloc_fake_hkey(const char *key_path) {
    pthread_mutex_lock(&g_hkey_lock);

    if (hkey_counter >= MAX_FAKE_HKEYS) {
        pthread_mutex_unlock(&g_hkey_lock);
        return NULL;
    }

    int idx = hkey_counter++;
    hkey_table[idx].used = 1;
    strncpy(hkey_table[idx].key_path, key_path, sizeof(hkey_table[idx].key_path) - 1);
    hkey_table[idx].key_path[sizeof(hkey_table[idx].key_path) - 1] = '\0';

    pthread_mutex_unlock(&g_hkey_lock);
    return (HKEY)(uintptr_t)(0x1000 + idx);
}

static void free_fake_hkey(HKEY hKey) {
    int idx = (int)((uintptr_t)hKey - 0x1000);
    if (idx < 0 || idx >= MAX_FAKE_HKEYS) return;

    pthread_mutex_lock(&g_hkey_lock);
    hkey_table[idx].used = 0;
    hkey_table[idx].key_path[0] = '\0';
    pthread_mutex_unlock(&g_hkey_lock);
}

static int copy_fake_hkey_path(HKEY hKey, char *out, size_t out_sz) {
    int idx = (int)((uintptr_t)hKey - 0x1000);
    if (idx < 0 || idx >= MAX_FAKE_HKEYS || !out || out_sz == 0) return 0;

    pthread_mutex_lock(&g_hkey_lock);
    int ok = hkey_table[idx].used;
    if (ok) {
        strncpy(out, hkey_table[idx].key_path, out_sz - 1);
        out[out_sz - 1] = '\0';
    }
    pthread_mutex_unlock(&g_hkey_lock);
    return ok;
}

static const char *find_value(LPCSTR value_name) {
    if (!value_name) return NULL;
    for (int i = 0; g_values[i].name; i++) {
        if (strcmp(g_values[i].name, value_name) == 0) {
            return g_values[i].value;
        }
    }
    return NULL;
}

LONG RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, DWORD samDesired, HKEY *phkResult) {
    (void)ulOptions;
    (void)samDesired;

    if (!lpSubKey || !phkResult) return ERROR_FILE_NOT_FOUND;

    char full_path[MAX_KEY_PATH];
    if ((uintptr_t)hKey < 0x1000) {
        snprintf(full_path, sizeof(full_path), "%s", lpSubKey);
    } else {
        char base[MAX_KEY_PATH];
        if (!copy_fake_hkey_path(hKey, base, sizeof(base))) {
            return ERROR_INVALID_HANDLE;
        }
        snprintf(full_path, sizeof(full_path), "%s\\%s", base, lpSubKey);
    }

    HKEY fake = alloc_fake_hkey(full_path);
    if (!fake) return ERROR_NOT_ENOUGH_MEMORY;

    *phkResult = fake;
    return ERROR_SUCCESS;
}

LONG RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    (void)lpReserved;

    char keybuf[MAX_KEY_PATH];
    if (!copy_fake_hkey_path(hKey, keybuf, sizeof(keybuf))) {
        return ERROR_INVALID_HANDLE;
    }

    const char *value = find_value(lpValueName);
    if (!value) return ERROR_FILE_NOT_FOUND;

    DWORD need = (DWORD)(strlen(value) + 1);
    if (lpType) *lpType = REG_SZ;

    if (!lpcbData) return ERROR_MORE_DATA;
    if (!lpData || *lpcbData < need) {
        *lpcbData = need;
        return ERROR_MORE_DATA;
    }

    memcpy(lpData, value, need);
    *lpcbData = need;
    return ERROR_SUCCESS;
}

LONG RegCloseKey(HKEY hKey) {
    if ((uintptr_t)hKey >= 0x1000) {
        free_fake_hkey(hKey);
    }
    return ERROR_SUCCESS;
}
