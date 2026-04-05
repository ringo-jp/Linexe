/*
 * Linexe - Heap API Hook (Phase 2)
 * Licensed under Apache License 2.0
 *
 * WindowsヒープAPIをmallocベースに変換する。
 *
 * 対応API:
 *   HeapCreate / HeapDestroy
 *   HeapAlloc / HeapReAlloc / HeapFree
 *   HeapSize
 *   GetProcessHeap
 *   LocalAlloc / LocalFree
 *   GlobalAlloc / GlobalFree
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef LINEXE_QUIET
  #define HOOK_LOG(fmt, ...) fprintf(stderr, "[LINEXE/HEAP] " fmt "\n", ##__VA_ARGS__)
#else
  #define HOOK_LOG(fmt, ...)
#endif

typedef uint32_t DWORD;
typedef size_t   SIZE_T;
typedef void*    HANDLE;
typedef int      BOOL;

/* LocalAlloc/GlobalAllocフラグ */
#define LMEM_FIXED    0x0000
#define LMEM_ZEROINIT 0x0040
#define GMEM_FIXED    0x0000
#define GMEM_ZEROINIT 0x0040

/* HeapAllocフラグ */
#define HEAP_ZERO_MEMORY       0x00000008
#define HEAP_GENERATE_EXCEPTIONS 0x00000004

/* ════════════════════════════════════════════════
   偽ヒープハンドル
   HeapCreateが返すハンドルとしてmallocで確保した
   小さなヘッダを使う。
   ════════════════════════════════════════════════ */
typedef struct {
    uint32_t magic;    /* 0xHEAP1234で識別 */
    size_t   max_size;
    DWORD    flags;
} FAKE_HEAP;

#define HEAP_MAGIC 0xA1C0BEEF

/* プロセスデフォルトヒープ（シングルトン） */
static FAKE_HEAP* g_process_heap = NULL;

static FAKE_HEAP* get_or_create_process_heap(void) {
    if (!g_process_heap) {
        g_process_heap = malloc(sizeof(FAKE_HEAP));
        if (g_process_heap) {
            g_process_heap->magic    = HEAP_MAGIC;
            g_process_heap->max_size = 0; /* 無制限 */
            g_process_heap->flags    = 0;
        }
    }
    return g_process_heap;
}

/* ════════════════════════════════════════════════
   HeapCreate / HeapDestroy
   ════════════════════════════════════════════════ */
HANDLE HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {
    FAKE_HEAP* heap = malloc(sizeof(FAKE_HEAP));
    if (!heap) return NULL;
    heap->magic    = HEAP_MAGIC;
    heap->max_size = dwMaximumSize;
    heap->flags    = flOptions;
    HOOK_LOG("HeapCreate(init=%zu, max=%zu) -> %p",
             dwInitialSize, dwMaximumSize, heap);
    return (HANDLE)heap;
}

BOOL HeapDestroy(HANDLE hHeap) {
    FAKE_HEAP* heap = (FAKE_HEAP*)hHeap;
    if (!heap || heap->magic != HEAP_MAGIC) return 0;
    if (heap == g_process_heap) {
        /* プロセスヒープは破棄しない */
        HOOK_LOG("HeapDestroy(process heap) -> ignored");
        return 1;
    }
    HOOK_LOG("HeapDestroy(%p)", hHeap);
    heap->magic = 0;
    free(heap);
    return 1;
}

/* ════════════════════════════════════════════════
   GetProcessHeap
   ════════════════════════════════════════════════ */
HANDLE GetProcessHeap(void) {
    HANDLE h = (HANDLE)get_or_create_process_heap();
    HOOK_LOG("GetProcessHeap -> %p", h);
    return h;
}

/* ════════════════════════════════════════════════
   HeapAlloc / HeapReAlloc / HeapFree / HeapSize
   ════════════════════════════════════════════════ */

/*
 * Windowsのヒープブロックは先頭にサイズを埋め込んで
 * HeapSizeが返せるようにする。
 *
 * メモリレイアウト:
 *   [ size_t size ][ actual data ... ]
 *                  ^-- ユーザに返すポインタ
 */
#define HEAP_HDR_SIZE (sizeof(size_t))

void* HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    (void)hHeap;
    uint8_t* raw = malloc(HEAP_HDR_SIZE + dwBytes);
    if (!raw) return NULL;
    if (dwFlags & HEAP_ZERO_MEMORY) memset(raw, 0, HEAP_HDR_SIZE + dwBytes);
    memcpy(raw, &dwBytes, HEAP_HDR_SIZE);
    void* ptr = raw + HEAP_HDR_SIZE;
    HOOK_LOG("HeapAlloc(%zu) -> %p", dwBytes, ptr);
    return ptr;
}

void* HeapReAlloc(HANDLE hHeap, DWORD dwFlags,
                  void* lpMem, SIZE_T dwBytes) {
    (void)hHeap; (void)dwFlags;
    if (!lpMem) return HeapAlloc(hHeap, dwFlags, dwBytes);
    uint8_t* raw = (uint8_t*)lpMem - HEAP_HDR_SIZE;
    uint8_t* new_raw = realloc(raw, HEAP_HDR_SIZE + dwBytes);
    if (!new_raw) return NULL;
    memcpy(new_raw, &dwBytes, HEAP_HDR_SIZE);
    void* ptr = new_raw + HEAP_HDR_SIZE;
    HOOK_LOG("HeapReAlloc(%p, %zu) -> %p", lpMem, dwBytes, ptr);
    return ptr;
}

BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, void* lpMem) {
    (void)hHeap; (void)dwFlags;
    if (!lpMem) return 1;
    uint8_t* raw = (uint8_t*)lpMem - HEAP_HDR_SIZE;
    HOOK_LOG("HeapFree(%p)", lpMem);
    free(raw);
    return 1;
}

SIZE_T HeapSize(HANDLE hHeap, DWORD dwFlags, const void* lpMem) {
    (void)hHeap; (void)dwFlags;
    if (!lpMem) return (SIZE_T)-1;
    const uint8_t* raw = (const uint8_t*)lpMem - HEAP_HDR_SIZE;
    size_t sz;
    memcpy(&sz, raw, HEAP_HDR_SIZE);
    HOOK_LOG("HeapSize(%p) -> %zu", lpMem, sz);
    return sz;
}

/* ════════════════════════════════════════════════
   LocalAlloc / LocalFree
   （16bit互換API、Win32でも頻繁に使われる）
   ════════════════════════════════════════════════ */
void* LocalAlloc(DWORD uFlags, SIZE_T uBytes) {
    void* ptr = (uFlags & LMEM_ZEROINIT) ? calloc(1, uBytes) : malloc(uBytes);
    HOOK_LOG("LocalAlloc(%zu) -> %p", uBytes, ptr);
    return ptr;
}

void* LocalFree(void* hMem) {
    HOOK_LOG("LocalFree(%p)", hMem);
    free(hMem);
    return NULL; /* 成功時はNULLを返す */
}

void* LocalReAlloc(void* hMem, SIZE_T uBytes, DWORD uFlags) {
    (void)uFlags;
    void* old = hMem;
    void* ptr = realloc(hMem, uBytes);
    HOOK_LOG("LocalReAlloc(%p, %zu) -> %p", old, uBytes, ptr);
    return ptr;
}

/* ════════════════════════════════════════════════
   GlobalAlloc / GlobalFree
   （LocalAllocと同等、Win32では同じ実装でよい）
   ════════════════════════════════════════════════ */
void* GlobalAlloc(DWORD uFlags, SIZE_T dwBytes) {
    void* ptr = (uFlags & GMEM_ZEROINIT) ? calloc(1, dwBytes) : malloc(dwBytes);
    HOOK_LOG("GlobalAlloc(%zu) -> %p", dwBytes, ptr);
    return ptr;
}

void* GlobalFree(void* hMem) {
    HOOK_LOG("GlobalFree(%p)", hMem);
    free(hMem);
    return NULL;
}

/* ════════════════════════════════════════════════
   セルフテスト
   ════════════════════════════════════════════════ */
#ifdef LINEXE_TEST_HEAP
int main(void) {
    printf("=== Linexe Heap Hook - Self Test ===\n\n");

    /* HeapCreate / HeapAlloc / HeapFree / HeapDestroy */
    HANDLE h = HeapCreate(0, 4096, 0);
    printf("HeapCreate -> %p\n", h);

    void* p = HeapAlloc(h, HEAP_ZERO_MEMORY, 128);
    printf("HeapAlloc(128) -> %p\n", p);

    size_t sz = HeapSize(h, 0, p);
    printf("HeapSize -> %zu\n", sz);

    memcpy(p, "Linexe", 7);
    printf("Data check: \"%s\"\n", (char*)p);

    void* p2 = HeapReAlloc(h, 0, p, 256);
    printf("HeapReAlloc(256) -> %p\n", p2);

    HeapFree(h, 0, p2);
    HeapDestroy(h);

    /* GetProcessHeap */
    HANDLE ph = GetProcessHeap();
    void* mp = HeapAlloc(ph, 0, 64);
    printf("\nGetProcessHeap -> %p\n", ph);
    printf("HeapAlloc on process heap -> %p\n", mp);
    HeapFree(ph, 0, mp);

    /* LocalAlloc / GlobalAlloc */
    void* la = LocalAlloc(LMEM_ZEROINIT, 32);
    printf("\nLocalAlloc(32)  -> %p\n", la);
    LocalFree(la);

    void* ga = GlobalAlloc(GMEM_ZEROINIT, 32);
    printf("GlobalAlloc(32) -> %p\n", ga);
    GlobalFree(ga);

    printf("\n[+] Heap test done.\n");
    return 0;
}
#endif
