/*
 * Linexe - Self-Contained EXE Executor (Wine-free)
 * Licensed under Apache License 2.0
 *
 * Wine を一切使わずに Windows EXE を Linux で実行する。
 *
 * 実行フロー:
 *   1. PE ヘッダを検証（有効な EXE か確認）
 *   2. EXE に必要なインポート DLL を解析・ログ出力
 *   3. LD_PRELOAD で Linexe フックライブラリを注入
 *   4. Syscall Tracer (linexe-tracer) 経由で EXE を起動
 *   5. NT Syscall → Linux Syscall をリアルタイム変換
 *
 * 依存関係:
 *   - linexe_hook.so  (Phase 2 API 偽装)
 *   - linexe-tracer   (Phase 3 Syscall 変換エンジン)
 *
 * Wine への依存: ゼロ
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <libgen.h>

/* PE セクションローダー (pe_section_loader.c) */
int linexe_load_and_exec(const char* exe_path, int argc, char* const* argv);
#include <limits.h>

/* ════════════════════════════════════════════════
   PE 構造体（最小サブセット）
   ════════════════════════════════════════════════ */
typedef struct { uint16_t e_magic; uint8_t _pad[58]; uint32_t e_lfanew; } DOS_HDR;
typedef struct { uint16_t Machine; uint16_t NumberOfSections; uint8_t _pad[12];
                 uint16_t SizeOfOptionalHeader; uint16_t Characteristics; } COFF_HDR;
typedef struct { uint16_t Magic; uint8_t _pad[90];
                 uint32_t NumberOfRvaAndSizes; } OPT_HDR32;
typedef struct { uint16_t Magic; uint8_t _pad[106];
                 uint32_t NumberOfRvaAndSizes; } OPT_HDR64;
typedef struct { uint32_t VirtualAddress; uint32_t Size; } DATA_DIR;
typedef struct { uint32_t OriginalFirstThunk; uint32_t TimeDateStamp;
                 uint32_t ForwarderChain; uint32_t Name;
                 uint32_t FirstThunk; } IMPORT_DESC;

#define MZ_MAGIC  0x5A4D
#define PE_SIG    0x00004550
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1

/* ════════════════════════════════════════════════
   PE 検証・DLL 依存関係解析
   ════════════════════════════════════════════════ */
typedef struct {
    int     valid;
    int     is_64bit;
    uint16_t machine;
    char    dll_names[64][64];
    int     dll_count;
    int     has_d3d11;
    int     has_d3d12;
    int     has_dxgi;
    int     has_anticheat;
} PeInfo;

static int pe_read(int fd, off_t off, void* buf, size_t sz) {
    if (lseek(fd, off, SEEK_SET) < 0) return -1;
    return (size_t)read(fd, buf, sz) == sz ? 0 : -1;
}

static int pe_analyze(const char* path, PeInfo* out) {
    memset(out, 0, sizeof(*out));

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return -1; }

    DOS_HDR dos;
    if (pe_read(fd, 0, &dos, sizeof(dos)) < 0 || dos.e_magic != MZ_MAGIC) {
        fprintf(stderr, "[Linexe] Not a valid EXE (bad MZ magic)\n");
        close(fd); return -1;
    }

    uint32_t pe_sig;
    if (pe_read(fd, dos.e_lfanew, &pe_sig, 4) < 0 || pe_sig != PE_SIG) {
        fprintf(stderr, "[Linexe] Not a valid PE (bad signature)\n");
        close(fd); return -1;
    }

    COFF_HDR coff;
    if (pe_read(fd, dos.e_lfanew + 4, &coff, sizeof(coff)) < 0) {
        close(fd); return -1;
    }

    out->machine = coff.Machine;
    /* 0x8664 = AMD64, 0x014C = i386 */
    out->is_64bit = (coff.Machine == 0x8664);
    out->valid    = 1;

    /* Optional Header を読んでインポートディレクトリを特定 */
    off_t opt_off = dos.e_lfanew + 4 + sizeof(COFF_HDR);
    uint16_t opt_magic;
    if (pe_read(fd, opt_off, &opt_magic, 2) < 0) { close(fd); return 0; }

    uint32_t import_rva = 0;
    if (opt_magic == 0x020B) { /* PE32+ */
        OPT_HDR64 opt;
        if (pe_read(fd, opt_off, &opt, sizeof(opt)) == 0) {
            DATA_DIR idir;
            off_t ddir_off = opt_off + sizeof(opt) +
                             IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof(DATA_DIR);
            if (pe_read(fd, ddir_off, &idir, sizeof(idir)) == 0)
                import_rva = idir.VirtualAddress;
        }
    } else if (opt_magic == 0x010B) { /* PE32 */
        OPT_HDR32 opt;
        if (pe_read(fd, opt_off, &opt, sizeof(opt)) == 0) {
            DATA_DIR idir;
            off_t ddir_off = opt_off + sizeof(opt) +
                             IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof(DATA_DIR);
            if (pe_read(fd, ddir_off, &idir, sizeof(idir)) == 0)
                import_rva = idir.VirtualAddress;
        }
    }

    /* セクションテーブルから RVA → ファイルオフセット変換 */
    if (import_rva) {
        typedef struct { char Name[8]; uint32_t VirtualSize;
                         uint32_t VirtualAddress; uint32_t SizeOfRaw;
                         uint32_t PointerToRaw; uint8_t _pad[16]; } SEC;
        off_t sec_off = opt_off + coff.SizeOfOptionalHeader;

        for (int s = 0; s < coff.NumberOfSections && s < 96; s++) {
            SEC sec;
            if (pe_read(fd, sec_off + s * sizeof(sec), &sec, sizeof(sec)) < 0) break;
            if (import_rva >= sec.VirtualAddress &&
                import_rva < sec.VirtualAddress + sec.VirtualSize) {
                off_t import_off = sec.PointerToRaw +
                                   (import_rva - sec.VirtualAddress);
                /* Import Descriptor テーブルを読む */
                for (int d = 0; d < 64 && out->dll_count < 64; d++) {
                    IMPORT_DESC desc;
                    if (pe_read(fd, import_off + d * sizeof(desc),
                                &desc, sizeof(desc)) < 0) break;
                    if (!desc.Name) break; /* Name=0は終端 */

                    /* DLL 名を読む */
                    off_t name_off = sec.PointerToRaw +
                                     (desc.Name - sec.VirtualAddress);
                    char dll_name[64] = {0};
                    if (pe_read(fd, name_off, dll_name, sizeof(dll_name)-1) == 0) {
                        memcpy(out->dll_names[out->dll_count], dll_name, 63);
                        out->dll_names[out->dll_count][63]='\0';
                        out->dll_count++;

                        /* 注目DLLの検出 */
                        char lower[64];
                        for (int i=0; dll_name[i]&&i<63; i++)
                            lower[i]=(char)(dll_name[i]|0x20);
                        lower[63]='\0';
                        if (strstr(lower,"d3d11"))     out->has_d3d11=1;
                        if (strstr(lower,"d3d12"))     out->has_d3d12=1;
                        if (strstr(lower,"dxgi"))      out->has_dxgi =1;
                        if (strstr(lower,"easyanticheat")||
                            strstr(lower,"battleye")   ||
                            strstr(lower,"vgk")        ||
                            strstr(lower,"gameguard"))  out->has_anticheat=1;
                    }
                }
                break;
            }
        }
    }

    close(fd);
    return 0;
}

/* ════════════════════════════════════════════════
   自己パス解決（linexe_hook.so / linexe-tracer の場所）
   ════════════════════════════════════════════════ */
static void get_linexe_dir(char* dir_out, size_t sz) {
    char self[PATH_MAX] = {0};
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self)-1);
    if (n > 0) {
        strncpy(dir_out, dirname(self), sz-1);
    } else {
        strncpy(dir_out, ".", sz-1);
    }
}

/* ════════════════════════════════════════════════
   Linexe 実行エンジン（Wine不要）
   ════════════════════════════════════════════════ */
static int linexe_exec(const char* exe_path, char* const argv[],
                        int use_tracer) {
    char dir[PATH_MAX];
    get_linexe_dir(dir, sizeof(dir));

    char hook_path[PATH_MAX];
    strncpy(hook_path, dir, PATH_MAX - 20);
    hook_path[PATH_MAX-20] = '\0';
    strncat(hook_path, "/linexe_hook.so", 15);

    char tracer_path[PATH_MAX];
    strncpy(tracer_path, dir, PATH_MAX - 16);
    tracer_path[PATH_MAX-16] = '\0';
    strncat(tracer_path, "/linexe-tracer", 14);

    /* フックライブラリの存在確認 */
    struct stat st;
    if (stat(hook_path, &st) != 0) {
        fprintf(stderr,
            "[Linexe] Warning: %s not found. "
            "Build with 'make all' first.\n", hook_path);
    }

    if (use_tracer && stat(tracer_path, &st) == 0) {
        /* モード2: linexe-tracer 経由（Syscall変換あり） */
        printf("[Linexe] Starting with syscall tracer...\n");

        /* tracer の argv を構築 */
        int argc = 0;
        while (argv[argc]) argc++;

        char** tracer_argv = malloc((size_t)(argc + 4) * sizeof(char*));
        if (!tracer_argv) return 127;
        tracer_argv[0] = tracer_path;
        tracer_argv[1] = (char*)"--hook";
        tracer_argv[2] = hook_path;
        for (int i = 0; i < argc; i++) tracer_argv[i+3] = argv[i];
        tracer_argv[argc+3] = NULL;

        execv(tracer_path, tracer_argv);
        free(tracer_argv);
        perror("execv linexe-tracer");
        return 127;

    } else {
        /* モード1: PE セクションローダー（直接実行）*/
        printf("[Linexe] Starting with PE section loader (direct execution)...\n");

        /* LD_PRELOAD で hook ライブラリを注入した上で PE ローダーを呼ぶ */
        char* existing = getenv("LD_PRELOAD");
        char new_preload[PATH_MAX * 2];
        if (existing && existing[0])
            snprintf(new_preload, sizeof(new_preload), "%s:%s", hook_path, existing);
        else
            snprintf(new_preload, sizeof(new_preload), "%s", hook_path);
        setenv("LD_PRELOAD", new_preload, 1);

        /* argc/argv の末尾を数える */
        int exe_argc = 0;
        while (argv[exe_argc]) exe_argc++;

        return linexe_load_and_exec(exe_path, exe_argc, argv);
    }
}

/* ════════════════════════════════════════════════
   エントリポイント
   ════════════════════════════════════════════════ */
static void print_usage(const char* prog) {
    fprintf(stderr,
        "Linexe v0.5.1 - Wine-free Windows EXE compatibility layer\n"
        "Usage:\n"
        "  %s <file.exe> [args...]         # 実行（tracer自動検出）\n"
        "  %s --hook-only <file.exe> [args] # LD_PRELOADのみ（軽量）\n"
        "  %s --analyze <file.exe>          # PE解析のみ（実行しない）\n"
        "  %s --version                     # バージョン表示\n",
        prog, prog, prog, prog);
}

int main(int argc, char* argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    if (strcmp(argv[1], "--version") == 0) {
        printf("Linexe v0.5.1\n"
               "Phases: PE-Loader + API-Hook + Syscall-Tracer"
               " + D3D11->Vulkan + KVM-AntiCheat\n"
               "Wine dependency: NONE\n");
        return 0;
    }

    int hook_only = 0;
    int analyze_only = 0;
    int exe_idx = 1;

    if (strcmp(argv[1], "--hook-only") == 0) { hook_only=1; exe_idx=2; }
    else if (strcmp(argv[1], "--analyze") == 0) { analyze_only=1; exe_idx=2; }

    if (exe_idx >= argc) { print_usage(argv[0]); return 1; }

    const char* exe_path = argv[exe_idx];

    /* ── PE 解析 ── */
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  Linexe v0.5.1  │  Wine-free EXE Runtime   ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");
    printf("[*] Target: %s\n", exe_path);

    PeInfo info;
    if (pe_analyze(exe_path, &info) < 0) return 1;
    if (!info.valid) { fprintf(stderr, "[Linexe] Invalid PE file.\n"); return 1; }

    printf("[*] Architecture : %s (%s)\n",
           info.is_64bit ? "x86-64" : "x86-32",
           info.machine == 0x8664 ? "AMD64" :
           info.machine == 0x014C ? "i386"  : "other");
    printf("[*] Import DLLs  : %d found\n", info.dll_count);
    for (int i = 0; i < info.dll_count; i++)
        printf("    [%2d] %s\n", i+1, info.dll_names[i]);

    printf("\n[*] Feature detection:\n");
    printf("    DirectX 11   : %s\n", info.has_d3d11 ? "YES → Vulkan bridge active" : "No");
    printf("    DirectX 12   : %s\n", info.has_d3d12 ? "YES (stub)" : "No");
    printf("    DXGI         : %s\n", info.has_dxgi  ? "YES" : "No");
    printf("    Anti-cheat   : %s\n", info.has_anticheat ? "YES → KVM hybrid mode" : "No");

    if (analyze_only) {
        printf("\n[*] --analyze mode: not executing.\n");
        return 0;
    }

    /* ── 実行 ── */
    printf("\n[*] Launching (Wine-free mode)...\n");
    printf("[*] Hook layer    : linexe_hook.so\n");
    printf("[*] Syscall engine: %s\n\n",
           hook_only ? "disabled (--hook-only)" : "linexe-tracer");

    return linexe_exec(exe_path, argv + exe_idx, !hook_only);
}
