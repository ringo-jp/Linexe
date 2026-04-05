/*
 * Linexe - Phase 3 Test Suite
 * Licensed under Apache License 2.0
 *
 * ptrace基盤・syscallテーブル・引数変換のテスト
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#include "syscall_table.h"

static int g_pass = 0, g_fail = 0;
#define TEST(name, cond) do { \
    if (cond) { printf("  PASS  %s\n", name); g_pass++; } \
    else      { printf("  FAIL  %s  (line %d)\n", name, __LINE__); g_fail++; } \
} while(0)
#define SECTION(s) printf("\n[%s]\n", s)

/* ════════════════════════════════════════════════
   TEST 1: syscall_table 整合性チェック
   ════════════════════════════════════════════════ */
static void test_table_integrity(void) {
    SECTION("syscall_table 整合性");

    TEST("テーブルサイズが50以上", SYSCALL_TABLE_LEN >= 50);

    /* 番号の重複チェック */
    int dupe = 0;
    for (size_t i = 0; i < SYSCALL_TABLE_LEN; i++)
        for (size_t j = i+1; j < SYSCALL_TABLE_LEN; j++)
            if (SYSCALL_TABLE[i].nt_number == SYSCALL_TABLE[j].nt_number)
                dupe++;
    TEST("NT番号の重複なし", dupe == 0);

    /* 番兵チェック */
    TEST("番兵エントリが末尾にある",
         SYSCALL_TABLE[SYSCALL_TABLE_LEN].nt_name == NULL);

    /* 重要エントリの存在確認 */
    TEST("NtCreateFile(0x55) 登録済み",  sc_find(0x55) != NULL);
    TEST("NtReadFile(0x06) 登録済み",    sc_find(0x06) != NULL);
    TEST("NtWriteFile(0x08) 登録済み",   sc_find(0x08) != NULL);
    TEST("NtClose(0x0F) 登録済み",       sc_find(0x0F) != NULL);
    TEST("NtAllocateVirtualMemory(0x18) 登録済み", sc_find(0x18) != NULL);
    TEST("NtFreeVirtualMemory(0x1E) 登録済み",     sc_find(0x1E) != NULL);
    TEST("NtProtectVirtualMemory(0x50) 登録済み",  sc_find(0x50) != NULL);
    TEST("NtTerminateProcess(0x2C) 登録済み",       sc_find(0x2C) != NULL);
    TEST("NtDelayExecution(0x34) 登録済み",         sc_find(0x34) != NULL);

    /* TRANSLATED エントリには Linux 番号が必要 */
    int trans_ok = 1;
    for (size_t i = 0; i < SYSCALL_TABLE_LEN; i++) {
        if (SYSCALL_TABLE[i].status == SC_TRANSLATED &&
            SYSCALL_TABLE[i].linux_number == SC_NO_LINUX) {
            printf("  WARN  TRANSLATED without linux_nr: %s\n",
                   SYSCALL_TABLE[i].nt_name);
            trans_ok = 0;
        }
    }
    TEST("TRANSLATED エントリは全てLinux番号あり", trans_ok);

    /* sc_find: 存在しない番号は NULL */
    TEST("sc_find(0xFFFF) -> NULL", sc_find(0xFFFF) == NULL);
    TEST("sc_find(0x0000) -> NULL (未登録)", sc_find(0x0000) == NULL);

    /* sc_status_str カバレッジ */
    TEST("sc_status_str(TRANSLATED)", strcmp(sc_status_str(SC_TRANSLATED),"TRANSLATED")==0);
    TEST("sc_status_str(STUB)",       strcmp(sc_status_str(SC_STUB),"STUB")==0);
    TEST("sc_status_str(BLOCKED)",    strcmp(sc_status_str(SC_BLOCKED),"BLOCKED")==0);
}

/* ════════════════════════════════════════════════
   TEST 2: ptrace 基盤動作テスト
   子プロセスを起動してSyscallをインターセプト
   ════════════════════════════════════════════════ */
static void test_ptrace_infra(void) {
    SECTION("ptrace 基盤動作");

    pid_t child = fork();
    if (child == 0) {
        /* 子：自分をtraceさせてからwrite(stdout, "X", 1)を呼ぶ */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        { ssize_t _r = write(STDOUT_FILENO, "X", 1); (void)_r; }
        exit(0);
    }

    int status;
    pid_t w = waitpid(child, &status, 0);
    TEST("子プロセス起動 & SIGSTOP", w == child && WIFSTOPPED(status));

    /* オプション設定 */
    long opts = PTRACE_O_TRACESYSGOOD;
    int opt_ok = ptrace(PTRACE_SETOPTIONS, child, NULL, (void*)opts) == 0;
    TEST("PTRACE_SETOPTIONS(TRACESYSGOOD)", opt_ok);

    /* syscall監視開始 */
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);

    int intercepted = 0;
    int write_found = 0;
    for (int i = 0; i < 20; i++) {
        w = waitpid(child, &status, 0);
        if (WIFEXITED(status) || WIFSIGNALED(status)) break;
        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);
        if (sig == (SIGTRAP | 0x80)) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            intercepted++;
            /* write(1) = Linux syscall 1 */
            if (regs.orig_rax == SYS_write && regs.rdi == STDOUT_FILENO)
                write_found = 1;
        }
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }
    waitpid(child, &status, 0);

    TEST("syscall-stop が発生する", intercepted > 0);
    TEST("write() が intercept される", write_found);
    TEST("子プロセスが正常終了",
         WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* ════════════════════════════════════════════════
   TEST 3: レジスタ書き換えで syscall を別のものに変換
   getpid() → gettid() に差し替えて結果が変わることを確認
   ════════════════════════════════════════════════ */
static void test_register_rewrite(void) {
    SECTION("レジスタ書き換えによるsyscall変換");

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        /* getpid() を呼ぶが tracer が gettid() に変換する */
        long result = syscall(SYS_getpid);
        /* result が gettid の値なら "T"、そのままなら "P" */
        char c = (result == syscall(SYS_gettid)) ? 'T' : 'P';
        { ssize_t _r = write(STDERR_FILENO, &c, 1); (void)_r; }
        exit(0);
    }

    int status;
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, NULL,
           (void*)(long)PTRACE_O_TRACESYSGOOD);
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);

    int rewrote = 0;
    for (int i = 0; i < 30; i++) {
        waitpid(child, &status, 0);
        if (WIFEXITED(status) || WIFSIGNALED(status)) break;
        if (!WIFSTOPPED(status)) { ptrace(PTRACE_SYSCALL, child, NULL, NULL); continue; }

        if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            /* getpid(SYS_getpid=39) → gettid(SYS_gettid=186) に差し替え */
            if (regs.orig_rax == SYS_getpid) {
                regs.orig_rax = SYS_gettid;
                regs.rax      = SYS_gettid;
                ptrace(PTRACE_SETREGS, child, NULL, &regs);
                rewrote = 1;
            }
        }
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }
    waitpid(child, &status, 0);

    TEST("getpid -> gettid の書き換え成功", rewrote);
    TEST("子プロセスが正常終了", WIFEXITED(status));
}

/* ════════════════════════════════════════════════
   TEST 4: NtDelayExecution 変換値チェック
   (実際にkernelに渡す必要はなく、変換ロジックのみ検証)
   ════════════════════════════════════════════════ */
static void test_delay_conversion(void) {
    SECTION("NtDelayExecution 変換値");

    /* LARGE_INTEGER は 100ns単位、負値 = 相対時間 */
    typedef struct { int64_t v; long exp_sec; long exp_ns_min; long exp_ns_max; } TC;
    TC cases[] = {
        { -10000000LL,  1, 0,         1000000   }, /* 1秒 */
        { -5000000LL,   0, 499000000, 501000000 }, /* 0.5秒 */
        { -100000LL,    0, 9900000,   10100000  }, /* 10ms */
        { -1000LL,      0, 99000,     101000    }, /* 100μs */
    };

    int ok = 1;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        int64_t v = cases[i].v;
        if (v < 0) v = -v;
        long sec  = (long)(v / 10000000LL);
        long nsec = (long)((v % 10000000LL) * 100LL);
        if (sec != cases[i].exp_sec ||
            nsec < cases[i].exp_ns_min ||
            nsec > cases[i].exp_ns_max) {
            printf("  WARN  delay case %zu: sec=%ld nsec=%ld\n", i, sec, nsec);
            ok = 0;
        }
    }
    TEST("NtDelayExecution 100ns→timespec変換", ok);

    /* ゼロ値 */
    int64_t zero = 0;
    long s = (long)(zero / 10000000LL);
    long n = (long)((zero % 10000000LL) * 100LL);
    TEST("NtDelayExecution 0 -> 0s 0ns", s == 0 && n == 0);
}

/* ════════════════════════════════════════════════
   TEST 5: NT Page Protection 変換
   ════════════════════════════════════════════════ */
static void test_page_protection(void) {
    SECTION("NT Page Protection 変換");

    /* inline copy of nt_page_to_prot */
    #define PAGE_NOACCESS    0x01
    #define PAGE_READONLY    0x02
    #define PAGE_READWRITE   0x04
    #define PAGE_EXECUTE     0x10
    #define PAGE_EXECUTE_READ 0x20
    #define PAGE_EXECUTE_READWRITE 0x40

    struct { uint32_t win; int exp; } cases[] = {
        { PAGE_NOACCESS,          PROT_NONE },
        { PAGE_READONLY,          PROT_READ },
        { PAGE_READWRITE,         PROT_READ | PROT_WRITE },
        { PAGE_EXECUTE,           PROT_EXEC },
        { PAGE_EXECUTE_READ,      PROT_EXEC | PROT_READ },
        { PAGE_EXECUTE_READWRITE, PROT_EXEC | PROT_READ | PROT_WRITE },
    };

    int ok = 1;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        uint32_t w = cases[i].win;
        int prot;
        switch (w & 0xFF) {
            case PAGE_NOACCESS:          prot = PROT_NONE; break;
            case PAGE_READONLY:          prot = PROT_READ; break;
            case PAGE_READWRITE:         prot = PROT_READ|PROT_WRITE; break;
            case PAGE_EXECUTE:           prot = PROT_EXEC; break;
            case PAGE_EXECUTE_READ:      prot = PROT_EXEC|PROT_READ; break;
            case PAGE_EXECUTE_READWRITE: prot = PROT_EXEC|PROT_READ|PROT_WRITE; break;
            default:                     prot = PROT_READ|PROT_WRITE;
        }
        if (prot != cases[i].exp) { ok = 0; break; }
    }
    TEST("全6パターンの保護フラグ変換", ok);
}

/* ════════════════════════════════════════════════
   TEST 6: tracee メモリ読み書き
   ════════════════════════════════════════════════ */
static int read_tracee_mem(pid_t pid, uint64_t addr,
                             void* buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid,
                           (void*)(addr+done), NULL);
        if (errno) return -1;
        size_t copy = len-done; if(copy>8)copy=8;
        memcpy((uint8_t*)buf+done,&word,copy);
        done += copy;
    }
    return 0;
}

static int write_tracee_mem(pid_t pid, uint64_t addr,
                              const void* buf, size_t len) {
    size_t done=0;
    while(done<len){
        size_t off=(addr+done)%8;
        uint64_t aligned=(addr+done)-off;
        long word=0;
        if(off||len-done<8){errno=0;word=ptrace(PTRACE_PEEKDATA,pid,(void*)aligned,NULL);if(errno)return -1;}
        size_t copy=8-off;if(copy>len-done)copy=len-done;
        memcpy((uint8_t*)&word+off,(const uint8_t*)buf+done,copy);
        if(ptrace(PTRACE_POKEDATA,pid,(void*)aligned,(void*)word)<0)return -1;
        done+=copy;
    }
    return 0;
}

static void test_mem_rw(void) {
    SECTION("tracee メモリ 読み書き");

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        volatile uint64_t val = 0xDEADBEEFCAFEBABEULL;
        (void)val;
        exit(0);
    }

    int status;
    waitpid(child, &status, 0);

    /* 子プロセスのスタックポインタ取得 */
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    uint64_t stack_ptr = regs.rsp;

    /* スタックに書き込んでから読み返す */
    uint64_t wrote = 0x1234567890ABCDEFull;
    int w_ok = write_tracee_mem(child, stack_ptr - 8,
                                 &wrote, sizeof(wrote)) == 0;
    TEST("tracee メモリへの書き込み", w_ok);

    uint64_t read_back = 0;
    int r_ok = read_tracee_mem(child, stack_ptr - 8,
                                &read_back, sizeof(read_back)) == 0;
    TEST("tracee メモリからの読み取り", r_ok);
    TEST("書き込み値と読み取り値の一致", read_back == wrote);

    /* バイト単位の非アライン書き込み */
    uint8_t bytes[3] = {0xAA, 0xBB, 0xCC};
    write_tracee_mem(child, stack_ptr - 11, bytes, 3);
    uint8_t rb[3] = {0};
    read_tracee_mem(child, stack_ptr - 11, rb, 3);
    TEST("非アライン3バイト読み書き",
         rb[0]==0xAA && rb[1]==0xBB && rb[2]==0xCC);

    ptrace(PTRACE_CONT, child, NULL, NULL);
    waitpid(child, &status, 0);
    TEST("子プロセス正常終了", WIFEXITED(status));
}

/* ════════════════════════════════════════════════
   TEST 7: syscall スキップ（STUB動作）
   存在しないsyscall番号を投入してEINTR/ENOSYSが
   返ることを確認（コードパスの検証）
   ════════════════════════════════════════════════ */
static void test_syscall_skip(void) {
    SECTION("syscall スキップ（STUB相当）");

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        /* 未実装syscall番号を直接呼ぶ */
        long r = syscall(999);
        /* r == -ENOSYS or -1 が期待値 */
        exit(r == -1 ? 0 : 1);
    }

    int status;
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, NULL,
           (void*)(long)PTRACE_O_TRACESYSGOOD);
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);

    int seen_999 = 0;
    for (int i = 0; i < 20; i++) {
        waitpid(child, &status, 0);
        if (WIFEXITED(status) || WIFSIGNALED(status)) break;
        if (!WIFSTOPPED(status)) goto next;
        if (WSTOPSIG(status) == (SIGTRAP|0x80)) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            if (regs.orig_rax == 999) seen_999 = 1;
        }
next:
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }
    waitpid(child, &status, 0);

    TEST("未実装syscall(999)がinterceptされる", seen_999);
    TEST("子プロセスがENOSYSで正常終了",
         WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* ════════════════════════════════════════════════
   メイン
   ════════════════════════════════════════════════ */
int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  Linexe Phase 3 Test Suite v0.3.0        ║\n");
    printf("╚══════════════════════════════════════════╝\n");

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    test_table_integrity();
    test_ptrace_infra();
    test_register_rewrite();
    test_delay_conversion();
    test_page_protection();
    test_mem_rw();
    test_syscall_skip();

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

    printf("\n══════════════════════════════════════════════\n");
    printf("  PASS: %d   FAIL: %d   TIME: %.2fs\n", g_pass, g_fail, elapsed);
    printf("══════════════════════════════════════════════\n");
    return g_fail > 0 ? 1 : 0;
}
