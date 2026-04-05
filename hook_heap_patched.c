/*
 * Linexe - Heap Hook Layer (patched draft)
 * Minimal implementation using libc malloc/free with basic safety.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef void* HANDLE;
typedef void* LPVOID;
typedef uint32_t DWORD;
typedef int BOOL;

#define TRUE 1
#define FALSE 0

HANDLE GetProcessHeap(void) {
    return (HANDLE)0x1; /* dummy */
}

LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, size_t dwBytes) {
    (void)hHeap;
    (void)dwFlags;
    void *p = malloc(dwBytes);
    return p;
}

BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
    (void)hHeap;
    (void)dwFlags;
    if (!lpMem) return TRUE;
    free(lpMem);
    return TRUE;
}

LPVOID HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, size_t dwBytes) {
    (void)hHeap;
    (void)dwFlags;
    if (!lpMem) return malloc(dwBytes);
    void *p = realloc(lpMem, dwBytes);
    return p;
}
