/*
 * Linexe - File / Memory Hook Layer (Phase 2)
 * Licensed under Apache License 2.0
 *
 * LD_PRELOAD で open/open64/mprotect をインターセプトし、
 * Windows パスを Linux パスへ変換する。
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <pthread.h>

#ifndef LINEXE_QUIET
  #define HOOK_LOG(fmt,...) fprintf(stderr,"[LINEXE/HOOK] " fmt "\n",##__VA_ARGS__)
#else
  #define HOOK_LOG(fmt,...)
#endif

/* ════════════════════════════════════════════════
   実関数ポインタ
   ════════════════════════════════════════════════ */
typedef int  (*open_fn)     (const char*, int, ...);
typedef int  (*mprotect_fn) (void*, size_t, int);

static struct {
    open_fn      real_open;
    open_fn      real_open64;
    mprotect_fn  real_mprotect;
} g_real;

static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

static void do_init(void) {
    g_real.real_open     = (open_fn)    dlsym(RTLD_NEXT, "open");
    g_real.real_open64   = (open_fn)    dlsym(RTLD_NEXT, "open64");
    g_real.real_mprotect = (mprotect_fn)dlsym(RTLD_NEXT, "mprotect");
}

static void ensure_init(void) {
    pthread_once(&g_init_once, do_init);
}

/* ════════════════════════════════════════════════
   Windows パス → Linux パス変換
   例: C:\Users\foo\bar.txt  →  /home/foo/bar.txt
       \Device\HarddiskVolume3\foo  →  /foo
   ════════════════════════════════════════════════ */
static void win_to_linux_path(const char* win, char* out, size_t sz) {
    if (!win || sz == 0) {
        if (out && sz > 0) out[0] = '\0';
        return;
    }

    /* すでに Linux パスならそのままコピー */
    if (win[0] == '/') {
        strncpy(out, win, sz - 1);
        out[sz - 1] = '\0';
        return;
    }

    /* ドライブレター除去: "C:\..." → "/..." */
    const char* src = win;
    if (((src[0] >= 'A' && src[0] <= 'Z') ||
         (src[0] >= 'a' && src[0] <= 'z')) && src[1] == ':') {
        src += 2;
    }

    /* バックスラッシュをスラッシュに変換 */
    size_t i = 0;
    if (src[0] != '\\' && src[0] != '/') {
        if (i < sz - 1) out[i++] = '/';
    }
    for (; *src && i < sz - 1; src++, i++) {
        out[i] = (*src == '\\') ? '/' : *src;
    }
    out[i] = '\0';
}

static void ensure_init(void);

int open(const char* pathname, int flags, ...) {
    ensure_init();

    if (!g_real.real_open) {
        errno = ENOSYS;
        return -1;
    }

    mode_t mode = 0;
    int need_mode = (flags & (O_CREAT | O_TMPFILE)) != 0;

    if (need_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    char linpath[4096];
    win_to_linux_path(pathname, linpath, sizeof(linpath));

    if (need_mode)
        return g_real.real_open(linpath, flags, mode);

    return g_real.real_open(linpath, flags);
}

int open64(const char* pathname, int flags, ...) {
    ensure_init();

    mode_t mode = 0;
    int need_mode = (flags & (O_CREAT | O_TMPFILE)) != 0;

    if (need_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    char linpath[4096];
    win_to_linux_path(pathname, linpath, sizeof(linpath));

    if (g_real.real_open64) {
        if (need_mode)
            return g_real.real_open64(linpath, flags, mode);
        return g_real.real_open64(linpath, flags);
    }

    if (!g_real.real_open) {
        errno = ENOSYS;
        return -1;
    }

    if (need_mode)
        return g_real.real_open(linpath, flags, mode);

    return g_real.real_open(linpath, flags);
}

int mprotect(void* addr, size_t len, int prot) {
    ensure_init();

    if (!g_real.real_mprotect) {
        errno = ENOSYS;
        return -1;
    }

    return g_real.real_mprotect(addr, len, prot);
}
