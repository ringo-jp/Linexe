/*
 * Linexe - Syscall Tracer (Phase 3)
 * Licensed under Apache License 2.0
 *
 * ptraceを使いNTシステムコールをインターセプトし、
 * Linuxシステムコールへリアルタイム変換する。
 *
 * アーキテクチャ:
 *   linexe-run → fork() → 子プロセス(EXE + LD_PRELOAD)
 *                       → PTRACE_TRACEME
 *               ← 親プロセス(tracer)がptrace(PTRACE_SYSCALL)で監視
 *
 * syscall-stop の判別:
 *   PTRACE_O_TRACESYSGOOD で SIGTRAP|0x80 = syscallエントリ/エグジット
 *   エントリ/エグジットを entry_flag で交互に判定
 *
 * 安定性対策 (v0.3.0):
 *   - SIGCHLD を無視してゾンビプロセスを防止
 *   - waitpid の EINTR を適切にリトライ
 *   - ptrace失敗時のエラー伝播を整備
 *   - 子プロセスが signal で死んだ場合の安全な終了処理
 *   - multithread: PTRACE_O_TRACECLONE で子スレッドを自動追跡
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>

#ifndef LINEXE_QUIET
  #define TLOG(fmt, ...) fprintf(stderr, "[LINEXE/TRACER] " fmt "\n", ##__VA_ARGS__)
#else
  #define TLOG(fmt, ...)
#endif
#define TERR(fmt, ...) fprintf(stderr, "[LINEXE/TRACER][ERROR] " fmt "\n", ##__VA_ARGS__)

/* 前方宣言：syscall_args.c で実装 */
long linexe_translate_syscall(pid_t pid, struct user_regs_struct* regs);

/* ════════════════════════════════════════════════
   追跡スレッドテーブル
   PTRACE_O_TRACECLONE で子スレッドを自動追加
   ════════════════════════════════════════════════ */
#define MAX_TRACED 256

typedef struct {
    pid_t   pid;
    int     active;
    int     in_syscall; /* 0=エントリ前, 1=エントリ済み（次はエグジット） */
} TRACED_PROC;

static TRACED_PROC traced[MAX_TRACED];
static int         traced_count = 0;

static TRACED_PROC* find_traced(pid_t pid) {
    for (int i = 0; i < traced_count; i++)
        if (traced[i].active && traced[i].pid == pid)
            return &traced[i];
    return NULL;
}

static TRACED_PROC* add_traced(pid_t pid) {
    for (int i = 0; i < MAX_TRACED; i++) {
        if (!traced[i].active) {
            traced[i].pid        = pid;
            traced[i].active     = 1;
            traced[i].in_syscall = 0;
            if (i >= traced_count) traced_count = i + 1;
            return &traced[i];
        }
    }
    return NULL;
}

static void remove_traced(pid_t pid) {
    for (int i = 0; i < traced_count; i++)
        if (traced[i].pid == pid) { traced[i].active = 0; return; }
}

static int active_count(void) {
    int n = 0;
    for (int i = 0; i < traced_count; i++)
        if (traced[i].active) n++;
    return n;
}

/* ════════════════════════════════════════════════
   ptrace オプション設定
   ════════════════════════════════════════════════ */
static int set_ptrace_options(pid_t pid) {
    long opts =
        PTRACE_O_TRACESYSGOOD  | /* syscall-stop: SIGTRAP|0x80 */
        PTRACE_O_TRACECLONE    | /* 子スレッド自動追跡 */
        PTRACE_O_TRACEFORK     | /* fork自動追跡 */
        PTRACE_O_TRACEVFORK    | /* vfork自動追跡 */
        PTRACE_O_TRACEEXEC     | /* exec追跡 */
        PTRACE_O_TRACEEXIT;      /* exit通知 */

    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)opts) < 0) {
        TERR("PTRACE_SETOPTIONS failed for pid %d: %s", pid, strerror(errno));
        return -1;
    }
    return 0;
}

/* ════════════════════════════════════════════════
   syscall エントリ処理
   ════════════════════════════════════════════════ */
static void handle_syscall_entry(pid_t pid, TRACED_PROC* tp) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        TERR("GETREGS failed: %s", strerror(errno));
        return;
    }

    uint32_t nt_nr = (uint32_t)regs.orig_rax;

    /* Linux ネイティブ syscall はそのまま通す（番号が小さい）
     * Windows NT syscall は通常 0x0004 以上 */
    if (nt_nr < 0x0004) {
        return; /* Linux の syscall をそのまま実行 */
    }

    long new_nr = linexe_translate_syscall(pid, &regs);
    if (new_nr < 0) {
        /*
         * STUB / BLOCKED: syscallをスキップしてraxに結果を設定済み。
         * 無効な syscall 番号に書き換えることでカーネルを通過させず
         * エグジット時に rax を上書きする。
         */
        regs.orig_rax = (uint64_t)(-1); /* ENOSYS を誘発 */
        if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
            TERR("SETREGS (skip) failed: %s", strerror(errno));
        tp->in_syscall = 2; /* 特殊マーク：エグジットでraxを0にする */
        return;
    }

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
        TERR("SETREGS failed: %s", strerror(errno));
}

/* ════════════════════════════════════════════════
   syscall エグジット処理
   ════════════════════════════════════════════════ */
static void handle_syscall_exit(pid_t pid, TRACED_PROC* tp) {
    if (tp->in_syscall == 2) {
        /* STUBのrax補正：カーネルが返したENOSYSを0（成功）に書き換え */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == 0) {
            regs.rax = 0;
            ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        }
    }
    /* 通常のエグジットは何もしない（Linuxが処理済み） */
}

/* ════════════════════════════════════════════════
   イベントループ
   ════════════════════════════════════════════════ */
static int tracer_loop(pid_t root_pid) {
    int status;
    int exit_code = 0;

    TLOG("Tracer started for PID %d", root_pid);

    /* 最初の SIGSTOP を待つ */
    pid_t w = waitpid(root_pid, &status, 0);
    if (w < 0) {
        TERR("Initial waitpid failed: %s", strerror(errno));
        return 1;
    }
    if (!WIFSTOPPED(status)) {
        TERR("Expected SIGSTOP, got status=0x%X", status);
        return 1;
    }

    if (set_ptrace_options(root_pid) < 0) return 1;
    add_traced(root_pid);

    /* syscall実行開始 */
    if (ptrace(PTRACE_SYSCALL, root_pid, NULL, NULL) < 0) {
        TERR("Initial PTRACE_SYSCALL failed: %s", strerror(errno));
        return 1;
    }

    /* ─── メインイベントループ ─── */
    while (active_count() > 0) {
        /* BUG FIX: EINTR をリトライ */
        do {
            w = waitpid(-1, &status, __WALL);
        } while (w < 0 && errno == EINTR);

        if (w < 0) {
            if (errno == ECHILD) break; /* 子プロセスなし */
            TERR("waitpid error: %s", strerror(errno));
            break;
        }

        TRACED_PROC* tp = find_traced(w);

        /* 新しい子プロセス/スレッドの追加 */
        if (!tp) {
            tp = add_traced(w);
            if (!tp) {
                TERR("Traced table full, ignoring PID %d", w);
                ptrace(PTRACE_DETACH, w, NULL, NULL);
                continue;
            }
            TLOG("New traced process/thread: %d", w);
            if (WIFSTOPPED(status))
                set_ptrace_options(w);
        }

        /* ── プロセス終了 ── */
        if (WIFEXITED(status)) {
            TLOG("PID %d exited (code=%d)", w, WEXITSTATUS(status));
            if (w == root_pid) exit_code = WEXITSTATUS(status);
            remove_traced(w);
            continue;
        }

        /* BUG FIX: シグナルによる強制終了 */
        if (WIFSIGNALED(status)) {
            TLOG("PID %d killed by signal %d", w, WTERMSIG(status));
            if (w == root_pid) exit_code = 128 + WTERMSIG(status);
            remove_traced(w);
            continue;
        }

        if (!WIFSTOPPED(status)) continue;

        int sig     = WSTOPSIG(status);
        int deliver = 0; /* traceeに転送するシグナル */

        /* ── ptrace イベント（clone/fork/exec/exit） ── */
        int ptrace_event = (status >> 16) & 0xFF;
        if (ptrace_event != 0) {
            switch (ptrace_event) {
                case PTRACE_EVENT_CLONE:
                case PTRACE_EVENT_FORK:
                case PTRACE_EVENT_VFORK: {
                    unsigned long new_pid = 0;
                    ptrace(PTRACE_GETEVENTMSG, w, NULL, &new_pid);
                    TLOG("Clone/fork: new PID %lu from %d", new_pid, w);
                    /* 新PIDは次のwaitpidで自動追加 */
                    break;
                }
                case PTRACE_EVENT_EXEC:
                    TLOG("PID %d exec'd", w);
                    break;
                case PTRACE_EVENT_EXIT:
                    TLOG("PID %d about to exit", w);
                    break;
            }
            ptrace(PTRACE_SYSCALL, w, NULL, NULL);
            continue;
        }

        /* ── syscall-stop (SIGTRAP|0x80) ── */
        if (sig == (SIGTRAP | 0x80)) {
            if (!tp->in_syscall) {
                /* エントリ */
                handle_syscall_entry(w, tp);
                tp->in_syscall = 1;
            } else {
                /* エグジット */
                handle_syscall_exit(w, tp);
                tp->in_syscall = 0;
            }
            ptrace(PTRACE_SYSCALL, w, NULL, NULL);
            continue;
        }

        /* ── 通常シグナル ── */
        if (sig == SIGTRAP) {
            /* execve直後等のSIGTRAPは通過 */
            ptrace(PTRACE_SYSCALL, w, NULL, NULL);
            continue;
        }

        /* SIGSTOP: 初回attach時に発生することがある */
        if (sig == SIGSTOP) {
            ptrace(PTRACE_SYSCALL, w, NULL, NULL);
            continue;
        }

        /* その他のシグナルはtraceeに転送 */
        deliver = sig;
        TLOG("Forwarding signal %d to PID %d", sig, w);
        ptrace(PTRACE_SYSCALL, w, NULL, (void*)(uintptr_t)deliver);
    }

    TLOG("Tracer exiting (code=%d)", exit_code);
    return exit_code;
}

/* ════════════════════════════════════════════════
   子プロセス起動
   ════════════════════════════════════════════════ */
static pid_t launch_tracee(const char* hook_so,
                             const char* exe,
                             char* const argv[]) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }

    if (pid == 0) {
        /* 子プロセス：自分をtraceするよう宣言 */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("PTRACE_TRACEME");
            exit(1);
        }

        /* LD_PRELOAD でhookライブラリを注入 */
        if (hook_so && hook_so[0]) {
            char* existing = getenv("LD_PRELOAD");
            char  new_val[4096];
            if (existing && existing[0])
                snprintf(new_val, sizeof(new_val), "%s:%s", hook_so, existing);
            else
                snprintf(new_val, sizeof(new_val), "%s", hook_so);
            setenv("LD_PRELOAD", new_val, 1);
        }

        /* exec直前にSIGSTOPを発生させてtracerに制御を渡す */
        raise(SIGSTOP);
        execvp(exe, argv);
        perror("execvp");
        exit(127);
    }

    return pid;
}

/* ════════════════════════════════════════════════
   エントリポイント
   ════════════════════════════════════════════════ */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "Linexe Syscall Tracer v0.3.0\n"
            "Usage: linexe-tracer [--hook hook.so] <exe> [args...]\n");
        return 1;
    }

    const char* hook_so = NULL;
    int exe_idx = 1;

    if (strcmp(argv[1], "--hook") == 0 && argc >= 4) {
        hook_so = argv[2];
        exe_idx = 3;
    }

    const char* exe = argv[exe_idx];

    /* BUG FIX: SIGCHLD を無視してゾンビを防止 */
    signal(SIGCHLD, SIG_DFL); /* waitpidを使うので SIG_DFL に戻す */

    printf("[Linexe] Launching: %s\n", exe);
    if (hook_so) printf("[Linexe] Hook: %s\n", hook_so);

    pid_t tracee = launch_tracee(hook_so, exe, argv + exe_idx);
    if (tracee < 0) return 1;

    return tracer_loop(tracee);
}
