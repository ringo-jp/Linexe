/*
 * Linexe - PE Loader (Phase 1)
 * Licensed under Apache License 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ─── DOS Header ─────────────────────────────────────────── */
typedef struct {
    uint16_t e_magic;     /* 0x5A4D "MZ" */
    uint8_t  _pad[58];
    uint32_t e_lfanew;    /* Offset to PE header */
} DOS_HEADER;

/* ─── COFF Header ────────────────────────────────────────── */
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_HEADER;

/* ─── Optional Header (PE32+) ────────────────────────────── */
typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOSVersion;
    uint16_t MinorOSVersion;
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
} OPT_HEADER;

/* ─── Section Header ─────────────────────────────────────── */
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
} SECTION_HEADER;

#define SEC_EXEC  0x20000000
#define SEC_READ  0x40000000
#define SEC_WRITE 0x80000000

static int read_exact(FILE *f, void *buf, size_t size) {
    return fread(buf, 1, size, f) == size;
}

static long get_file_size(FILE *f) {
    long cur = ftell(f);
    if (cur < 0) return -1;
    if (fseek(f, 0, SEEK_END) != 0) return -1;
    long end = ftell(f);
    if (end < 0) return -1;
    if (fseek(f, cur, SEEK_SET) != 0) return -1;
    return end;
}

static const char* subsystem_name(uint16_t s) {
    switch (s) {
        case 2:  return "Windows GUI";
        case 3:  return "Windows CUI (Console)";
        case 9:  return "Windows CE GUI";
        case 14: return "Xbox";
        default: return "Unknown";
    }
}

static void section_perms(uint32_t c, char* out) {
    out[0] = (c & SEC_READ)  ? 'R' : '-';
    out[1] = (c & SEC_WRITE) ? 'W' : '-';
    out[2] = (c & SEC_EXEC)  ? 'X' : '-';
    out[3] = '\0';
}

static int load_exe(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }

    DOS_HEADER dos;
    if (!read_exact(f, &dos, sizeof(dos))) {
        fprintf(stderr, "[!] Failed to read DOS header\n");
        fclose(f);
        return 1;
    }
    if (dos.e_magic != 0x5A4D) {
        fprintf(stderr, "[!] Not a valid EXE (missing MZ magic)\n");
        fclose(f);
        return 1;
    }

    long fsize = get_file_size(f);
    if (fsize < 0) {
        fprintf(stderr, "[!] Failed to determine file size\n");
        fclose(f);
        return 1;
    }
    if (dos.e_lfanew == 0 || (long)dos.e_lfanew > fsize - 4) {
        fprintf(stderr, "[!] Invalid e_lfanew: 0x%X\n", dos.e_lfanew);
        fclose(f);
        return 1;
    }
    printf("[*] MZ magic OK  (offset to PE: 0x%X)\n", dos.e_lfanew);

    if (fseek(f, (long)dos.e_lfanew, SEEK_SET) != 0) {
        fprintf(stderr, "[!] Failed to seek to PE header\n");
        fclose(f);
        return 1;
    }

    uint32_t sig;
    if (!read_exact(f, &sig, sizeof(sig))) {
        fprintf(stderr, "[!] Failed to read PE signature\n");
        fclose(f);
        return 1;
    }
    if (sig != 0x00004550) {
        fprintf(stderr, "[!] PE signature mismatch\n");
        fclose(f);
        return 1;
    }
    printf("[*] PE signature OK\n");

    COFF_HEADER coff;
    if (!read_exact(f, &coff, sizeof(coff))) {
        fprintf(stderr, "[!] Failed to read COFF header\n");
        fclose(f);
        return 1;
    }
    printf("\n── COFF Header ─────────────────────────\n");
    printf("    Machine        : 0x%04X (%s)\n", coff.Machine,
           coff.Machine == 0x8664 ? "x86-64" :
           coff.Machine == 0x014C ? "x86-32" : "other");
    printf("    Sections       : %d\n", coff.NumberOfSections);
    printf("    Characteristics: 0x%04X%s%s\n",
           coff.Characteristics,
           (coff.Characteristics & 0x2000) ? " [DLL]" : "",
           (coff.Characteristics & 0x0002) ? " [EXE]" : "");

    OPT_HEADER opt;
    if (!read_exact(f, &opt, sizeof(opt))) {
        fprintf(stderr, "[!] Failed to read Optional header\n");
        fclose(f);
        return 1;
    }
    printf("\n── Optional Header ─────────────────────\n");
    printf("    Magic          : 0x%04X (%s)\n", opt.Magic,
           opt.Magic == 0x020B ? "PE32+ 64bit" :
           opt.Magic == 0x010B ? "PE32 32bit"  : "unknown");
    printf("    ImageBase      : 0x%016llX\n", (unsigned long long)opt.ImageBase);
    printf("    EntryPoint RVA : 0x%08X\n", opt.AddressOfEntryPoint);
    printf("    SizeOfImage    : 0x%X (%u KB)\n",
           opt.SizeOfImage, opt.SizeOfImage / 1024);
    printf("    Subsystem      : %s\n", subsystem_name(opt.Subsystem));

    long sec_offset = (long)dos.e_lfanew + 4L + (long)sizeof(COFF_HEADER) + (long)coff.SizeOfOptionalHeader;
    if (sec_offset < 0 || sec_offset > fsize) {
        fprintf(stderr, "[!] Invalid section table offset\n");
        fclose(f);
        return 1;
    }
    if (fseek(f, sec_offset, SEEK_SET) != 0) {
        fprintf(stderr, "[!] Failed to seek to section table\n");
        fclose(f);
        return 1;
    }

    printf("\n── Sections ────────────────────────────\n");
    printf("    %-8s  %-10s  %-10s  %-10s  %s\n",
           "Name", "VirtAddr", "VirtSize", "RawSize", "Perms");
    printf("    %s\n", "──────────────────────────────────────────────────");

    for (int i = 0; i < coff.NumberOfSections; i++) {
        SECTION_HEADER sec;
        if (!read_exact(f, &sec, sizeof(sec))) {
            fprintf(stderr, "[!] Failed to read section header %d\n", i);
            fclose(f);
            return 1;
        }
        char perms[4];
        section_perms(sec.Characteristics, perms);
        printf("    %-8.8s  0x%08X  0x%08X  0x%08X  %s\n",
               sec.Name, sec.VirtualAddress,
               sec.VirtualSize, sec.SizeOfRawData, perms);
    }

    printf("\n[+] PE parse complete. Ready for Phase 2.\n");
    fclose(f);
    return 0;
}

int main(int argc, char** argv) {
    printf("╔══════════════════════════════════════╗\n");
    printf("║  Linexe  v0.1.0  -  Phase 1 Loader  ║\n");
    printf("╚══════════════════════════════════════╝\n\n");

    if (argc < 2) {
        fprintf(stderr, "Usage: linexe <file.exe>\n");
        return 1;
    }
    printf("[*] Target: %s\n\n", argv[1]);
    return load_exe(argv[1]);
}
