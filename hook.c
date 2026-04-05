
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
