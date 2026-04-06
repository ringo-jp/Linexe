/*
 * Linexe - PE Section Loader (Phase 1 実装)
 * Licensed under Apache License 2.0
 *
 * 実際に EXE をメモリに展開して実行する。
 * Wine を使わない純粋な Linux 上の PE 実行パス。
 *
 * 対象: PE32+ (x86-64) のみ
 * 前提: linexe_hook.so が LD_PRELOAD で注入済み
 *       (Windows API 呼び出しが Linux 実装に透過変換される)
 *
 * 実装範囲:
 *   DONE  セクションの mmap（RVA → 仮想アドレス）
 *   DONE  ベースリロケーション（ASLR 有効EXEの再配置）
 *   DONE  インポートテーブル解決（IAT を dlsym で埋める）
 *   DONE  TLS コールバック実行
 *   DONE  entry_point への制御移譲
 *
 *   PARTIAL  インポートDLL → Linux 実装のマッピング
 *            (kernel32/ntdll/user32 は hook.so でカバー)
 *
 *   NOT_YET  例外ハンドリング (SEH / VEH)
 *   NOT_YET  スレッドローカルストレージ (完全)
 *   NOT_YET  遅延ロード (DELAYIMPORT)
 *
 * 使い方:
 *   linexe_load_and_exec("game.exe", argc, argv);
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdarg.h>

/* ════════════════════════════════════════════════
   PE 構造体定義（完全版）
   ════════════════════════════════════════════════ */
typedef struct { uint16_t e_magic; uint8_t _[58]; uint32_t e_lfanew; } DOS_HDR;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_HDR;

typedef struct {
    uint16_t Magic;             /* 0x020B = PE32+ */
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint; /* RVA */
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
} OPT64_HDR;

typedef struct { uint32_t VirtualAddress; uint32_t Size; } DATA_DIR;
#define NDIR 16
#define DIR_EXPORT    0
#define DIR_IMPORT    1
#define DIR_BASERELOC 5
#define DIR_TLS       9

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} SEC_HDR;

#define SEC_CNT_CODE       0x00000020
#define SEC_CNT_INIT_DATA  0x00000040
#define SEC_CNT_UNINIT     0x00000080
#define SEC_MEM_EXECUTE    0x20000000
#define SEC_MEM_READ       0x40000000
#define SEC_MEM_WRITE      0x80000000

/* Import Descriptor */
typedef struct {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;           /* RVA to DLL name */
    uint32_t FirstThunk;     /* RVA to IAT */
} IMPORT_DESC;

/* Thunk Data (IMAGE_THUNK_DATA64) */
typedef struct {
    union {
        uint64_t ForwarderString;
        uint64_t Function;
        uint64_t Ordinal;          /* bit63=1 → ordinal */
        uint64_t AddressOfData;    /* bit63=0 → RVA to IMPORT_BY_NAME */
    } u;
} THUNK64;
#define THUNK_ORDINAL_FLAG 0x8000000000000000ULL

/* IMAGE_IMPORT_BY_NAME */
typedef struct {
    uint16_t Hint;
    char     Name[1];
} IMPORT_BY_NAME;

/* Base Relocation */
typedef struct {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
} BASE_RELOC;
#define IMAGE_REL_BASED_DIR64 10

/* TLS Directory (PE32+) */
typedef struct {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks; /* 関数ポインタ配列 */
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
} TLS_DIR64;

/* ════════════════════════════════════════════════
   DLL名 → Linux 実装 のマッピング
   ════════════════════════════════════════════════
 * Windows DLL の関数を Linux の実装に引き当てる。
 * linexe_hook.so が LD_PRELOAD されていることが前提。
 * そこで定義されていない関数はシンボル検索で解決を試みる。
 */
typedef struct {
    const char* win_dll;   /* DLL名（大文字小文字無視） */
    const char* linux_lib; /* dlopen するライブラリ (NULL=プロセス内検索) */
} DLL_MAP;

static const DLL_MAP DLL_MAPPINGS[] = {
    { "kernel32.dll",   NULL },  /* hook_*.c でカバー */
    { "kernelbase.dll", NULL },
    { "ntdll.dll",      NULL },
    { "user32.dll",     NULL },
    { "gdi32.dll",      NULL },
    { "advapi32.dll",   NULL },
    { "shell32.dll",    NULL },
    { "ole32.dll",      NULL },
    { "oleaut32.dll",   NULL },
    { "ws2_32.dll",     NULL },
    { "winmm.dll",      NULL },
    { "d3d11.dll",      NULL },  /* d3d11_hook.c でカバー */
    { "dxgi.dll",       NULL },
    { "msvcrt.dll",     "libmsvcrt.so"  }, /* 試みる */
    { "ucrtbase.dll",   NULL },
    { NULL,             NULL }
};

/* ════════════════════════════════════════════════
   ローダー内部状態
   ════════════════════════════════════════════════ */
typedef struct {
    void*    image_base;      /* メモリ上のロードアドレス */
    uint64_t preferred_base;  /* EXE が希望するアドレス */
    uint64_t image_size;
    uint32_t entry_rva;
    DATA_DIR dirs[NDIR];
    int      num_sections;
    SEC_HDR  sections[96];
    void*    file_data;       /* ファイル全体のメモリマップ */
    size_t   file_size;
    void*    open_libs[64];   /* dlopen ハンドル */
    int      open_lib_count;
} PE_IMAGE;

static void pe_log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[Linexe/PE] ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* RVA → ポインタ変換 */
static void* rva_to_ptr(PE_IMAGE* img, uint32_t rva) {
    return (uint8_t*)img->image_base + rva;
}

/* ════════════════════════════════════════════════
   STEP 1: ファイルをメモリに読み込む
   ════════════════════════════════════════════════ */
static int pe_read_file(PE_IMAGE* img, const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return -1; }

    struct stat st;
    fstat(fd, &st);
    img->file_size = (size_t)st.st_size;
    img->file_data = mmap(NULL, img->file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (img->file_data == MAP_FAILED) { perror("mmap file"); return -1; }
    return 0;
}

/* ════════════════════════════════════════════════
   STEP 2: PE ヘッダ解析
   ════════════════════════════════════════════════ */
static int pe_parse_headers(PE_IMAGE* img) {
    const uint8_t* data = (const uint8_t*)img->file_data;

    const DOS_HDR* dos = (const DOS_HDR*)data;
    if (dos->e_magic != 0x5A4D) { pe_log("Not MZ"); return -1; }

    uint32_t pe_sig;
    memcpy(&pe_sig, data + dos->e_lfanew, 4);
    if (pe_sig != 0x00004550) { pe_log("Not PE"); return -1; }

    const COFF_HDR* coff = (const COFF_HDR*)(data + dos->e_lfanew + 4);
    if (coff->Machine != 0x8664) {
        pe_log("Not x86-64 (machine=0x%04X)", coff->Machine);
        return -1;
    }

    const OPT64_HDR* opt = (const OPT64_HDR*)((uint8_t*)(coff + 1));
    if (opt->Magic != 0x020B) { pe_log("Not PE32+"); return -1; }

    img->preferred_base = opt->ImageBase;
    img->image_size     = opt->SizeOfImage;
    img->entry_rva      = opt->AddressOfEntryPoint;

    /* データディレクトリ */
    const DATA_DIR* dirs = (const DATA_DIR*)(opt + 1);
    int ndir = opt->NumberOfRvaAndSizes < NDIR ? opt->NumberOfRvaAndSizes : NDIR;
    for (int i = 0; i < ndir; i++) img->dirs[i] = dirs[i];

    /* セクションヘッダ */
    img->num_sections = coff->NumberOfSections;
    const SEC_HDR* secs = (const SEC_HDR*)((uint8_t*)opt + coff->SizeOfOptionalHeader);
    int nsec = coff->NumberOfSections < 96 ? coff->NumberOfSections : 96;
    for (int i = 0; i < nsec; i++) img->sections[i] = secs[i];

    pe_log("PE32+ x86-64: base=0x%llX entry=0x%X sections=%d",
           (unsigned long long)img->preferred_base,
           img->entry_rva, img->num_sections);
    return 0;
}

/* ════════════════════════════════════════════════
   STEP 3: セクションを仮想メモリに展開
   ════════════════════════════════════════════════ */
static int pe_map_sections(PE_IMAGE* img) {
    const uint8_t* file = (const uint8_t*)img->file_data;

    /* まず preferred_base に MAP_FIXED_NOREPLACE で試みる */
    void* base = mmap((void*)img->preferred_base, img->image_size,
                      PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                      -1, 0);
    if (base == MAP_FAILED) {
        /* preferred_base が使えない → ASLR でどこかに配置 */
        base = mmap(NULL, img->image_size,
                    PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) { perror("mmap image"); return -1; }
        pe_log("ASLR: loaded at %p (preferred 0x%llX)",
               base, (unsigned long long)img->preferred_base);
    } else {
        pe_log("Loaded at preferred base %p", base);
    }
    img->image_base = base;

    /* ヘッダを書き込む */
    mprotect(base, 0x1000, PROT_READ | PROT_WRITE);
    memcpy(base, file, 0x1000 < img->file_size ? 0x1000 : img->file_size);

    /* 各セクションをマップ */
    for (int i = 0; i < img->num_sections; i++) {
        const SEC_HDR* s = &img->sections[i];
        if (!s->VirtualAddress || !s->VirtualSize) continue;

        uint8_t* sec_addr = (uint8_t*)base + s->VirtualAddress;
        uint32_t map_size = s->VirtualSize;
        /* ページ境界に揃える */
        map_size = (map_size + 0xFFF) & ~0xFFFU;

        /* 書き込み可能にして内容をコピー */
        mprotect(sec_addr, map_size, PROT_READ | PROT_WRITE);

        if (s->SizeOfRawData > 0) {
            uint32_t copy_sz = s->SizeOfRawData < s->VirtualSize
                             ? s->SizeOfRawData : s->VirtualSize;
            memcpy(sec_addr, file + s->PointerToRawData, copy_sz);
        }
        /* 未初期化部分はゼロ（mmap 済みなので既にゼロ） */

        /* 最終パーミッション設定 */
        int prot = PROT_READ;
        if (s->Characteristics & SEC_MEM_WRITE)   prot |= PROT_WRITE;
        if (s->Characteristics & SEC_MEM_EXECUTE)  prot |= PROT_EXEC;
        mprotect(sec_addr, map_size, prot);

        pe_log("  Section %-8.8s VA=0x%08X sz=0x%X prot=%c%c%c",
               s->Name, s->VirtualAddress, s->VirtualSize,
               (prot & PROT_READ)  ? 'R' : '-',
               (prot & PROT_WRITE) ? 'W' : '-',
               (prot & PROT_EXEC)  ? 'X' : '-');
    }
    return 0;
}

/* ════════════════════════════════════════════════
   STEP 4: ベースリロケーション
   （ロードアドレスが preferred_base と異なる場合のみ）
   ════════════════════════════════════════════════ */
static int pe_apply_relocations(PE_IMAGE* img) {
    int64_t delta = (int64_t)(uintptr_t)img->image_base
                  - (int64_t)img->preferred_base;
    if (delta == 0) { pe_log("Relocation: not needed"); return 0; }

    DATA_DIR* reloc_dir = &img->dirs[DIR_BASERELOC];
    if (!reloc_dir->VirtualAddress || !reloc_dir->Size) {
        pe_log("Relocation: no .reloc section (DLL_CHARACTERISTICS_FIXED_BASE?)");
        /* リロケーションなし → preferred_base からずれた状態では動かない可能性 */
        return 0;
    }

    pe_log("Relocation: delta=0x%llX", (unsigned long long)(uint64_t)delta);

    uint8_t* reloc_start = (uint8_t*)rva_to_ptr(img, reloc_dir->VirtualAddress);
    uint8_t* reloc_end   = reloc_start + reloc_dir->Size;
    uint8_t* p           = reloc_start;

    int count = 0;
    while (p < reloc_end) {
        const BASE_RELOC* block = (const BASE_RELOC*)p;
        if (!block->VirtualAddress || !block->SizeOfBlock) break;

        uint32_t num_entries = (block->SizeOfBlock - sizeof(BASE_RELOC)) / 2;
        const uint16_t* entries = (const uint16_t*)(block + 1);

        for (uint32_t i = 0; i < num_entries; i++) {
            uint16_t type   = entries[i] >> 12;
            uint16_t offset = entries[i] & 0x0FFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                uint64_t* target = (uint64_t*)rva_to_ptr(img,
                    block->VirtualAddress + offset);
                /* 書き込み可能にしてパッチ */
                mprotect((void*)((uintptr_t)target & ~0xFFFULL), 0x1000,
                         PROT_READ | PROT_WRITE);
                *target += (uint64_t)(int64_t)delta;
                count++;
            }
        }
        p += block->SizeOfBlock;
    }

    pe_log("Relocation: %d entries patched", count);
    return 0;
}

/* ════════════════════════════════════════════════
   STEP 5: インポートテーブル解決（IAT を dlsym で埋める）
   ════════════════════════════════════════════════ */

/* DLL名から dlopen ハンドルを取得 */
static void* open_dll(PE_IMAGE* img, const char* dll_name_raw) {
    /* 大文字→小文字 */
    char dll_name[128]; int i=0;
    for (; dll_name_raw[i] && i < 127; i++)
        dll_name[i] = (char)((dll_name_raw[i] >= 'A' && dll_name_raw[i] <= 'Z')
                             ? dll_name_raw[i] + 32 : dll_name_raw[i]);
    dll_name[i] = '\0';

    /* マッピングテーブルで確認 */
    for (int j = 0; DLL_MAPPINGS[j].win_dll; j++) {
        if (strcmp(DLL_MAPPINGS[j].win_dll, dll_name) == 0) {
            if (!DLL_MAPPINGS[j].linux_lib)
                return RTLD_DEFAULT; /* 現在のプロセス内（hook.so に定義済み）*/
            /* ライブラリ名を試みる */
            void* h = dlopen(DLL_MAPPINGS[j].linux_lib, RTLD_LAZY | RTLD_GLOBAL);
            if (h) {
                if (img->open_lib_count < 64)
                    img->open_libs[img->open_lib_count++] = h;
                return h;
            }
        }
    }

    pe_log("  Import: unknown DLL '%s' (using process symbols)", dll_name);
    return RTLD_DEFAULT;
}

static int pe_resolve_imports(PE_IMAGE* img) {
    DATA_DIR* imp_dir = &img->dirs[DIR_IMPORT];
    if (!imp_dir->VirtualAddress || !imp_dir->Size) {
        pe_log("No imports"); return 0;
    }

    const IMPORT_DESC* desc = (const IMPORT_DESC*)rva_to_ptr(img, imp_dir->VirtualAddress);
    int total_resolved = 0, total_failed = 0;

    for (; desc->Name; desc++) {
        const char* dll_name = (const char*)rva_to_ptr(img, desc->Name);
        void* dll_handle = open_dll(img, dll_name);

        pe_log("  Import: %s", dll_name);

        /* INT (OriginalFirstThunk) または ILT がなければ IAT で代替 */
        uint32_t ilt_rva = desc->OriginalFirstThunk
                         ? desc->OriginalFirstThunk : desc->FirstThunk;
        THUNK64* ilt = (THUNK64*)rva_to_ptr(img, ilt_rva);
        THUNK64* iat = (THUNK64*)rva_to_ptr(img, desc->FirstThunk);

        /* IAT を書き込み可能に */
        mprotect((void*)((uintptr_t)iat & ~0xFFFULL), 0x2000,
                 PROT_READ | PROT_WRITE);

        for (int k = 0; ilt[k].u.AddressOfData; k++) {
            const char* sym_name = NULL;
            char ordinal_buf[32];

            if (ilt[k].u.Ordinal & THUNK_ORDINAL_FLAG) {
                /* オーディナル import */
                uint16_t ord = (uint16_t)(ilt[k].u.Ordinal & 0xFFFF);
                snprintf(ordinal_buf, sizeof(ordinal_buf), "#%u", ord);
                sym_name = ordinal_buf;
            } else {
                /* 名前 import */
                const IMPORT_BY_NAME* ibn = (const IMPORT_BY_NAME*)
                    rva_to_ptr(img, (uint32_t)ilt[k].u.AddressOfData);
                sym_name = ibn->Name;
            }

            void* fn = dlsym(dll_handle, sym_name);
            if (!fn && dll_handle != RTLD_DEFAULT)
                fn = dlsym(RTLD_DEFAULT, sym_name); /* フォールバック */

            if (fn) {
                iat[k].u.Function = (uint64_t)(uintptr_t)fn;
                total_resolved++;
            } else {
                pe_log("    UNRESOLVED: %s!%s", dll_name, sym_name);
                /* NULL を残す → 呼ばれたら SIGSEGV するがローダー自体は続行 */
                total_failed++;
            }
        }
    }

    pe_log("Import resolution: %d resolved, %d unresolved",
           total_resolved, total_failed);
    if (total_failed > 0) {
        pe_log("WARNING: %d unresolved imports. EXE may crash at runtime.",
               total_failed);
    }
    return total_failed > 0 ? 1 : 0; /* 警告だが致命的ではない */
}

/* ════════════════════════════════════════════════
   STEP 6: TLS コールバック実行
   ════════════════════════════════════════════════ */
typedef void (*TLS_CALLBACK)(void* DllHandle, uint32_t Reason, void* Reserved);

static void pe_run_tls_callbacks(PE_IMAGE* img) {
    DATA_DIR* tls_dir = &img->dirs[DIR_TLS];
    if (!tls_dir->VirtualAddress || !tls_dir->Size) return;

    const TLS_DIR64* tls = (const TLS_DIR64*)rva_to_ptr(img, tls_dir->VirtualAddress);
    if (!tls->AddressOfCallBacks) return;

    TLS_CALLBACK* cbs = (TLS_CALLBACK*)(uintptr_t)tls->AddressOfCallBacks;
    for (int i = 0; cbs[i]; i++) {
        pe_log("TLS callback[%d]: %p", i, (void*)(uintptr_t)cbs[i]);
        cbs[i](img->image_base, 1 /* DLL_PROCESS_ATTACH */, NULL);
    }
}

/* ════════════════════════════════════════════════
   STEP 7: entry_point へジャンプ
   ════════════════════════════════════════════════ */
typedef int (*ENTRY_POINT)(void); /* WinMain / mainCRTStartup */

static int pe_transfer_control(PE_IMAGE* img) {
    ENTRY_POINT ep = (ENTRY_POINT)(
        (uint8_t*)img->image_base + img->entry_rva);

    pe_log("Transferring control to entry_point %p", (void*)(uintptr_t)ep);
    pe_log("──────────────────────────────────────────");

    /* entry_point を実行 */
    /* Windows のエントリポイントは通常 mainCRTStartup() または WinMainCRTStartup()
     * どちらも最終的に ExitProcess(exit_code) を呼ぶ。
     * Linexe ではそれを exit(n) にフックしている。 */
    int ret = ep();
    return ret;
}

/* ════════════════════════════════════════════════
   公開 API
   ════════════════════════════════════════════════ */
int linexe_load_and_exec(const char* exe_path, int argc, char* const* argv) {
    (void)argc; (void)argv;

    pe_log("Loading '%s'", exe_path);

    PE_IMAGE img;
    memset(&img, 0, sizeof(img));

    if (pe_read_file(&img, exe_path)    < 0) return 1;
    if (pe_parse_headers(&img)          < 0) return 1;
    if (pe_map_sections(&img)           < 0) return 1;
    if (pe_apply_relocations(&img)      < 0) return 1;
    pe_resolve_imports(&img);   /* unresolved は警告のみ */
    pe_run_tls_callbacks(&img);

    /* セクションの実行権限を最終確認 */
    for (int i = 0; i < img.num_sections; i++) {
        const SEC_HDR* s = &img.sections[i];
        if ((s->Characteristics & SEC_MEM_EXECUTE) && s->VirtualAddress) {
            /* exec+write は危険なのでここで write を剥がす */
            uint8_t* p = (uint8_t*)img.image_base + s->VirtualAddress;
            mprotect(p, (s->VirtualSize + 0xFFF) & ~0xFFFU,
                     PROT_READ | PROT_EXEC);
        }
    }

    return pe_transfer_control(&img);
}

/* ════════════════════════════════════════════════
   スタンドアロンテスト用 main
   ════════════════════════════════════════════════ */
#ifdef LINEXE_PE_LOADER_MAIN
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "Linexe PE Loader - loads and executes Windows EXE (x86-64)\n"
            "Usage: %s <file.exe> [args...]\n"
            "Note: LD_PRELOAD=linexe_hook.so must be set for API hooking\n",
            argv[0]);
        return 1;
    }
    return linexe_load_and_exec(argv[1], argc - 1, argv + 1);
}
#endif /* LINEXE_PE_LOADER_MAIN */
