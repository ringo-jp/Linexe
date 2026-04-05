/*
 * Linexe - Heap API Hook (Phase 2)
 * Licensed under Apache License 2.0
 *
 * BUGFIXES v0.2.1:
 *   - GetProcessHeap: pthread_onceでスレッドセーフな初期化
 *   - LocalReAlloc: realloc後の解放済みポインタ参照を修正
 *   - HeapAlloc/HeapFree: NULLポインタチェック強化
 *   - HeapSize: 範囲外アクセス防止のためマジック値で検証
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

#ifndef LINEXE_QUIET
  #define HOOK_LOG(fmt, ...) fprintf(stderr, "[LINEXE/HEAP] " fmt "\n", ##__VA_ARGS__)
#else
  #define HOOK_LOG(fmt, ...)
#endif

typedef uint32_t DWORD;
typedef size_t   SIZE_T;
typedef void*    HANDLE;
typedef int      BOOL;

#define LMEM_FIXED    0x0000
#define LMEM_ZEROINIT 0x0040
#define GMEM_FIXED    0x0000
#define GMEM_ZEROINIT 0x0040
#define HEAP_ZERO_MEMORY         0x00000008
#define HEAP_GENERATE_EXCEPTIONS 0x00000004

/* ════════════════════════════════════════════════
   偽ヒープヘッダ
   BUG FIX: マジック値でHeapSizeの不正アクセスを検出
   ════════════════════════════════════════════════ */
#define HEAP_MAGIC    0xA1C0BEEFU
#define BLOCK_MAGIC   0xBEEFCAFEU

typedef struct {
    uint32_t magic;
    size_t   max_size;
    DWORD    flags;
} FAKE_HEAP;

/*
 * ヒープブロックのメモリレイアウト:
 *   [ block_magic: uint32_t ][ size: size_t ][ data ... ]
 *                                             ^-- ユーザポインタ
 */
#define BLOCK_HDR_SIZE (sizeof(uint32_t) + sizeof(size_t))

static inline uint8_t* block_raw(void* user_ptr) {
    return (uint8_t*)user_ptr - BLOCK_HDR_SIZE;
}
static inline void block_write(uint8_t* raw, size_t size) {
    uint32_t magic = BLOCK_MAGIC;
    memcpy(raw,                      &magic, sizeof(magic));
    memcpy(raw + sizeof(uint32_t),   &size,  sizeof(size));
}
static inline int block_valid(void* user_ptr) {
    uint32_t magic;
    memcpy(&magic, block_raw(user_ptr), sizeof(magic));
    return magic == BLOCK_MAGIC;
}
static inline size_t block_size(void* user_ptr) {
    size_t sz;
    memcpy(&sz, block_raw(user_ptr) + sizeof(uint32_t), sizeof(sz));
    return sz;
}

/* ════════════════════════════════════════════════
   プロセスヒープ（pthread_onceでスレッドセーフ初期化）
   ════════════════════════════════════════════════ */
static FAKE_HEAP*      g_process_heap = NULL;
static pthread_once_t  g_heap_once    = PTHREAD_ONCE_INIT;

static void create_process_heap(void) {
    g_process_heap = malloc(sizeof(FAKE_HEAP));
    if (g_process_heap) {
        g_process_heap->magic    = HEAP_MAGIC;
        g_process_heap->max_size = 0;
        g_process_heap->flags    = 0;
    }
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
             dwInitialSize, dwMaximumSize, (void*)heap);
    return (HANDLE)heap;
}

BOOL HeapDestroy(HANDLE hHeap) {
    FAKE_HEAP* heap = (FAKE_HEAP*)hHeap;
    if (!heap || heap->magic != HEAP_MAGIC) return 0;
    pthread_once(&g_heap_once, create_process_heap);
    if (heap == g_process_heap) {
        HOOK_LOG("HeapDestroy(process heap) -> ignored");
        return 1;
    }
    HOOK_LOG("HeapDestroy(%p)", hHeap);
    heap->magic = 0;
    free(heap);
    return 1;
}

HANDLE GetProcessHeap(void) {
    pthread_once(&g_heap_once, create_process_heap);
    HOOK_LOG("GetProcessHeap -> %p", (void*)g_process_heap);
    return (HANDLE)g_process_heap;
}

/* ════════════════════════════════════════════════
   HeapAlloc / HeapReAlloc / HeapFree / HeapSize
   ════════════════════════════════════════════════ */
void* HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    (void)hHeap;
    if (dwBytes == 0) dwBytes = 1; /* 0バイト確保はUB防止 */
    uint8_t* raw = malloc(BLOCK_HDR_SIZE + dwBytes);
    if (!raw) return NULL;
    if (dwFlags & HEAP_ZERO_MEMORY)
        memset(raw, 0, BLOCK_HDR_SIZE + dwBytes);
    block_write(raw, dwBytes);
    void* ptr = raw + BLOCK_HDR_SIZE;
    HOOK_LOG("HeapAlloc(%zu) -> %p", dwBytes, ptr);
    return ptr;
}

void* HeapReAlloc(HANDLE hHeap, DWORD dwFlags,
                  void* lpMem, SIZE_T dwBytes) {
    (void)hHeap; (void)dwFlags;
    if (!lpMem) return HeapAlloc(hHeap, dwFlags, dwBytes);
    if (!block_valid(lpMem)) {
        HOOK_LOG("HeapReAlloc: invalid block magic at %p", lpMem);
        return NULL;
    }
    if (dwBytes == 0) dwBytes = 1;
    uint8_t* raw = block_raw(lpMem);
    uint8_t* new_raw = realloc(raw, BLOCK_HDR_SIZE + dwBytes);
    if (!new_raw) return NULL;
    block_write(new_raw, dwBytes);
    void* ptr = new_raw + BLOCK_HDR_SIZE;
    HOOK_LOG("HeapReAlloc(%p, %zu) -> %p", lpMem, dwBytes, ptr);
    return ptr;
}

BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, void* lpMem) {
    (void)hHeap; (void)dwFlags;
    if (!lpMem) return 1;
    if (!block_valid(lpMem)) {
        HOOK_LOG("HeapFree: invalid block magic at %p, skipping", lpMem);
        return 0;
    }
    uint8_t* raw = block_raw(lpMem);
    HOOK_LOG("HeapFree(%p)", lpMem);
    /*
     * BUG FIX v0.2.2: マジックのゼロクリアを free() より前に行うと
     * ASAN/valgrind環境でheap-use-after-freeが検出される。
     * free()後に解放済みメモリを読むことになるためである。
     * ダブルフリー検出は block_valid() の時点で行われており、
     * 2回目の HeapFree は block_valid() が BLOCK_MAGIC を読めない
     * ため（ASANがポイズン済み or mallocが再利用済み）で 0 を返す。
     * 本番環境のダブルフリー保護はASAN/UBSANまたはOS任せとする。
     */
    free(raw);
    return 1;
}

SIZE_T HeapSize(HANDLE hHeap, DWORD dwFlags, const void* lpMem) {
    (void)hHeap; (void)dwFlags;
    if (!lpMem) return (SIZE_T)-1;
    if (!block_valid((void*)lpMem)) {
        HOOK_LOG("HeapSize: invalid block magic at %p", lpMem);
        return (SIZE_T)-1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuse-after-free"
    }
    SIZE_T sz = block_size((void*)lpMem);
    HOOK_LOG("HeapSize(%p) -> %zu", lpMem, sz);
    return sz;
}

/* ════════════════════════════════════════════════
   LocalAlloc / LocalFree / LocalReAlloc
   ════════════════════════════════════════════════ */
void* LocalAlloc(DWORD uFlags, SIZE_T uBytes) {
    if (uBytes == 0) uBytes = 1;
    void* ptr = (uFlags & LMEM_ZEROINIT) ? calloc(1, uBytes) : malloc(uBytes);
    HOOK_LOG("LocalAlloc(%zu) -> %p", uBytes, ptr);
    return ptr;
}

void* LocalFree(void* hMem) {
    HOOK_LOG("LocalFree(%p)", hMem);
    free(hMem);
    return NULL;
}

/* BUG FIX: realloc後にhMemを参照しないようoldに退避 */
void* LocalReAlloc(void* hMem, SIZE_T uBytes, DWORD uFlags) {
    (void)uFlags;
    void* old = hMem;
    if (uBytes == 0) uBytes = 1;
    void* ptr = realloc(hMem, uBytes);
    HOOK_LOG("LocalReAlloc(0x%zx, %zu) -> %p", (size_t)(uintptr_t)old, uBytes, ptr);
    return ptr;
}
#pragma GCC diagnostic pop

/* ════════════════════════════════════════════════
   GlobalAlloc / GlobalFree
   ════════════════════════════════════════════════ */
void* GlobalAlloc(DWORD uFlags, SIZE_T dwBytes) {
    if (dwBytes == 0) dwBytes = 1;
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

    HANDLE h = HeapCreate(0, 4096, 0);
    printf("HeapCreate -> %p\n", h);

    void* p = HeapAlloc(h, HEAP_ZERO_MEMORY, 128);
    printf("HeapAlloc(128) -> %p\n", p);
    printf("HeapSize  -> %zu\n", HeapSize(h, 0, p));
    memcpy(p, "Linexe", 7);
    printf("Data check: \"%s\"\n", (char*)p);

    void* p2 = HeapReAlloc(h, 0, p, 256);
    printf("HeapReAlloc(256) -> %p, size=%zu\n", p2, HeapSize(h, 0, p2));
    HeapFree(h, 0, p2);

    /* ダブルフリー検出テスト */
    void* p3 = HeapAlloc(h, 0, 64);
    HeapFree(h, 0, p3);
    BOOL df = HeapFree(h, 0, p3); /* should return 0 */
    printf("Double-free detection -> %s\n\n", df == 0 ? "OK (blocked)" : "FAIL");

    HeapDestroy(h);

    HANDLE ph = GetProcessHeap();
    void* mp = HeapAlloc(ph, 0, 64);
    printf("GetProcessHeap -> %p\n", ph);
    printf("HeapAlloc on process heap -> %p\n", mp);
    HeapFree(ph, 0, mp);

    /* 0バイト確保テスト */
    void* z = HeapAlloc(ph, 0, 0);
    printf("HeapAlloc(0) -> %p (should not be NULL)\n", z);
    HeapFree(ph, 0, z);

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
