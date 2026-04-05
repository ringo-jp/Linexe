/*
 * Linexe - KVM Hybrid Anti-Cheat Isolation (Phase 5)
 * Licensed under Apache License 2.0
 *
 * アーキテクチャ:
 *
 *   +─────────────────────────────────────────+
 *   │  Linux ホスト (Zorin OS 18)              │
 *   │                                          │
 *   │  ┌──────────────────────────────────┐   │
 *   │  │  Linexe (ゲーム本体)              │   │
 *   │  │  Phase 2: API偽装                │   │
 *   │  │  Phase 3: Syscall変換             │   │
 *   │  │  Phase 4: D3D11→Vulkan           │   │
 *   │  └──────────────┬───────────────────┘   │
 *   │                 │ KVM IPC bridge          │
 *   │  ┌──────────────▼───────────────────┐   │
 *   │  │  KVM Guest (最小Windowsカーネル)  │   │
 *   │  │  アンチチートドライバ (.sys)      │   │
 *   │  │  └ 整合性チェック → ホストへ報告  │   │
 *   │  └──────────────────────────────────┘   │
 *   +─────────────────────────────────────────+
 *
 * Phase 5 実装 (v0.5.0):
 *   DONE  KVM デバイス初期化 (/dev/kvm)
 *   DONE  VM 作成・メモリマッピング・vCPU設定
 *   DONE  Hypercall ベースの IPC チャンネル
 *   DONE  アンチチートドライバ状態管理
 *   DONE  整合性チェック応答の偽装
 *   DONE  KVM unavailable 時のフォールバック（ソフトウェアエミュ）
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>

/* KVM ヘッダ（linux/kvm.h の最小サブセット） */
#include <linux/kvm.h>

#ifndef LINEXE_QUIET
  #define KVM_LOG(fmt,...) fprintf(stderr,"[LINEXE/KVM] " fmt "\n",##__VA_ARGS__)
#else
  #define KVM_LOG(fmt,...)
#endif
#define KVM_ERR(fmt,...) fprintf(stderr,"[LINEXE/KVM][ERR] " fmt "\n",##__VA_ARGS__)

/* ════════════════════════════════════════════════
   KVM VM 状態
   ════════════════════════════════════════════════ */
#define KVM_GUEST_MEM_SIZE   (64 * 1024 * 1024)  /* 64MB ゲストメモリ */
#define KVM_GUEST_LOAD_ADDR  0x10000              /* カーネルロードアドレス */

/* Hypercall 番号（LinexeプライベートABI） */
#define LINEXE_HC_PING           0x4C58  /* 'LX' - 疎通確認 */
#define LINEXE_HC_INTEGRITY_OK   0x4C59  /* 整合性チェック成功を報告 */
#define LINEXE_HC_DRIVER_READY   0x4C5A  /* ドライバ初期化完了 */
#define LINEXE_HC_GAME_HASH      0x4C5B  /* ゲームバイナリのハッシュ送信 */
#define LINEXE_HC_SHUTDOWN       0x4C5C  /* VMシャットダウン要求 */

/* IPC 共有メモリ構造体 */
typedef struct {
    volatile uint32_t magic;           /* 0xAC1DC0DE */
    volatile uint32_t version;         /* プロトコルバージョン */
    volatile uint32_t ac_driver_state; /* 0=未ロード, 1=初期化中, 2=アクティブ */
    volatile uint32_t integrity_check; /* 0=未実施, 1=成功, 2=失敗 */
    volatile uint64_t game_hash;       /* FNV-1a ゲームバイナリハッシュ */
    volatile uint32_t check_count;     /* チェック実施回数 */
    volatile uint32_t last_error;      /* 最後のエラーコード */
    volatile uint8_t  heartbeat;       /* VM生存確認 */
    uint8_t           _pad[7];
    char              driver_name[64]; /* ロードされたドライバ名 */
    char              game_name[64];   /* ゲーム名 */
} __attribute__((packed)) LxIpcShm;

#define IPC_MAGIC 0xAC1DC0DEUL

/* KVM VMハンドル */
typedef struct {
    int      kvm_fd;       /* /dev/kvm */
    int      vm_fd;        /* VM ファイルディスクリプタ */
    int      vcpu_fd;      /* vCPU fd */
    void*    guest_mem;    /* ゲストメモリ (mmap) */
    size_t   guest_mem_size;
    LxIpcShm* ipc;          /* IPC共有メモリ（ゲストメモリ内） */
    struct kvm_run* run;    /* vCPU run 構造体 */
    size_t   run_size;
    pthread_t vcpu_thread;
    volatile int running;
    int      use_software_fallback; /* KVM不使用時=1 */
} LxKvmVm;

static LxKvmVm g_vm = {0};
static pthread_mutex_t g_vm_lock = PTHREAD_MUTEX_INITIALIZER;
static int             g_vm_inited = 0;

/* ════════════════════════════════════════════════
   ソフトウェアフォールバック（KVM不使用時）
   ════════════════════════════════════════════════
 *
 * /dev/kvm が使えない環境（コンテナ・一部VM）では
 * プロセス内でアンチチートの振る舞いをシミュレートする。
 * 実際のドライバは動かないが、API応答は偽装できる。
 */
static void software_fallback_init(LxKvmVm* vm) {
    vm->use_software_fallback = 1;

    /* IPC領域をホストメモリに確保 */
    vm->ipc = calloc(1, sizeof(LxIpcShm));
    if (!vm->ipc) return;

    vm->ipc->magic           = IPC_MAGIC;
    vm->ipc->version         = 1;
    vm->ipc->ac_driver_state = 2;  /* アクティブとして偽装 */
    vm->ipc->integrity_check = 1;  /* 成功として偽装 */
    vm->ipc->game_hash       = 0;
    vm->ipc->check_count     = 0;
    strncpy(vm->ipc->driver_name, "LinexeACShim", sizeof(vm->ipc->driver_name)-1);
    strncpy(vm->ipc->game_name,   "Unknown",      sizeof(vm->ipc->game_name)-1);

    KVM_LOG("Software fallback mode (KVM unavailable)");
}

/* ════════════════════════════════════════════════
   KVM 初期化
   ════════════════════════════════════════════════ */

/* x86 Real Mode の最小ブートコード（IPC セットアップ + HLT） */
static const uint8_t GUEST_BOOT_CODE[] = {
    /* 実アドレス 0x10000: ゲストコードエントリ */
    /* mov ax, 0x4C58   ; LINEXE_HC_PING */
    0xB8, 0x58, 0x4C,
    /* out 0x10, ax      ; Linexe hypercall port */
    0xE6, 0x10,
    /* mov ax, 0x4C5A   ; LINEXE_HC_DRIVER_READY */
    0xB8, 0x5A, 0x4C,
    0xE6, 0x10,
    /* mov ax, 0x4C59   ; LINEXE_HC_INTEGRITY_OK */
    0xB8, 0x59, 0x4C,
    0xE6, 0x10,
    /* hlt loop */
    0xF4,               /* hlt */
    0xEB, 0xFE,         /* jmp -2 (infinite loop) */
};

static int kvm_vm_init(LxKvmVm* vm) {
    /* /dev/kvm を開く */
    vm->kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (vm->kvm_fd < 0) {
        KVM_LOG("Cannot open /dev/kvm: %s (using software fallback)", strerror(errno));
        software_fallback_init(vm);
        return 0; /* フォールバックは成功とする */
    }

    /* KVM API バージョン確認 */
    int version = ioctl(vm->kvm_fd, KVM_GET_API_VERSION, 0);
    if (version != 12) {
        KVM_ERR("KVM API version %d != 12", version);
        close(vm->kvm_fd); vm->kvm_fd = -1;
        software_fallback_init(vm);
        return 0;
    }
    KVM_LOG("KVM API version: %d", version);

    /* VM 作成 */
    vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
    if (vm->vm_fd < 0) {
        KVM_ERR("KVM_CREATE_VM failed: %s", strerror(errno));
        goto fallback;
    }

    /* ゲストメモリ確保 */
    vm->guest_mem_size = KVM_GUEST_MEM_SIZE;
    vm->guest_mem = mmap(NULL, vm->guest_mem_size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                         -1, 0);
    if (vm->guest_mem == MAP_FAILED) {
        KVM_ERR("Guest memory mmap failed: %s", strerror(errno));
        goto fallback;
    }
    memset(vm->guest_mem, 0, vm->guest_mem_size);

    /* ブートコードをゲストメモリに配置 */
    memcpy((uint8_t*)vm->guest_mem + KVM_GUEST_LOAD_ADDR,
           GUEST_BOOT_CODE, sizeof(GUEST_BOOT_CODE));

    /* IPC 領域をゲストメモリの末尾に配置 */
    vm->ipc = (LxIpcShm*)((uint8_t*)vm->guest_mem
              + vm->guest_mem_size - sizeof(LxIpcShm));
    vm->ipc->magic   = IPC_MAGIC;
    vm->ipc->version = 1;

    /* ゲストメモリをVMにセット */
    struct kvm_userspace_memory_region mem_region = {
        .slot            = 0,
        .flags           = 0,
        .guest_phys_addr = 0,
        .memory_size     = vm->guest_mem_size,
        .userspace_addr  = (uint64_t)(uintptr_t)vm->guest_mem,
    };
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &mem_region) < 0) {
        KVM_ERR("KVM_SET_USER_MEMORY_REGION failed: %s", strerror(errno));
        goto fallback;
    }

    /* vCPU 作成 */
    vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vcpu_fd < 0) {
        KVM_ERR("KVM_CREATE_VCPU failed: %s", strerror(errno));
        goto fallback;
    }

    /* vCPU run 構造体のマップ */
    vm->run_size = (size_t)ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    vm->run = mmap(NULL, vm->run_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED, vm->vcpu_fd, 0);
    if (vm->run == MAP_FAILED) {
        KVM_ERR("vCPU mmap failed: %s", strerror(errno));
        goto fallback;
    }

    /* x86 Real Mode に設定 */
    struct kvm_sregs sregs;
    ioctl(vm->vcpu_fd, KVM_GET_SREGS, &sregs);
    sregs.cs.base     = 0;
    sregs.cs.selector = 0;
    ioctl(vm->vcpu_fd, KVM_SET_SREGS, &sregs);

    struct kvm_regs regs = {0};
    regs.rip   = KVM_GUEST_LOAD_ADDR;
    regs.rflags= 0x2; /* reserved bit always 1 */
    ioctl(vm->vcpu_fd, KVM_SET_REGS, &regs);

    KVM_LOG("KVM VM ready: vm_fd=%d vcpu_fd=%d guest_mem=%p",
            vm->vm_fd, vm->vcpu_fd, vm->guest_mem);
    return 0;

fallback:
    if (vm->guest_mem && vm->guest_mem != MAP_FAILED)
        munmap(vm->guest_mem, vm->guest_mem_size);
    if (vm->vcpu_fd >= 0) close(vm->vcpu_fd);
    if (vm->vm_fd >= 0)   close(vm->vm_fd);
    if (vm->kvm_fd >= 0)  close(vm->kvm_fd);
    vm->vcpu_fd = vm->vm_fd = vm->kvm_fd = -1;
    software_fallback_init(vm);
    return 0;
}

/* ════════════════════════════════════════════════
   vCPU 実行スレッド
   Hypercall（IO ポート 0x10 への OUT 命令）を処理する
   ════════════════════════════════════════════════ */
static void* vcpu_thread_fn(void* arg) {
    LxKvmVm* vm = (LxKvmVm*)arg;
    KVM_LOG("vCPU thread started");

    while (vm->running) {
        int r = ioctl(vm->vcpu_fd, KVM_RUN, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            KVM_ERR("KVM_RUN: %s", strerror(errno));
            break;
        }

        switch (vm->run->exit_reason) {
            case KVM_EXIT_HLT:
                KVM_LOG("Guest HLT - sleeping 10ms");
                usleep(10000);
                break;

            case KVM_EXIT_IO:
                if (vm->run->io.direction == KVM_EXIT_IO_OUT &&
                    vm->run->io.port == 0x10) {
                    /* Hypercall 処理 */
                    uint16_t hc = *(uint16_t*)((uint8_t*)vm->run +
                                   vm->run->io.data_offset);
                    switch (hc) {
                        case LINEXE_HC_PING:
                            vm->ipc->heartbeat = 1;
                            break;
                        case LINEXE_HC_DRIVER_READY:
                            vm->ipc->ac_driver_state = 2;
                            KVM_LOG("Anti-cheat driver READY");
                            break;
                        case LINEXE_HC_INTEGRITY_OK:
                            vm->ipc->integrity_check = 1;
                            vm->ipc->check_count++;
                            KVM_LOG("Integrity check #%u OK",
                                    vm->ipc->check_count);
                            break;
                        case LINEXE_HC_SHUTDOWN:
                            vm->running = 0;
                            KVM_LOG("Guest requested shutdown");
                            break;
                        default:
                            KVM_LOG("Unknown hypercall: 0x%04X", hc);
                    }
                }
                break;

            case KVM_EXIT_MMIO:
                /* MMIO は今のところ無視 */
                break;

            case KVM_EXIT_FAIL_ENTRY:
                KVM_ERR("KVM_EXIT_FAIL_ENTRY: hw_entry_failure=0x%llx",
                        (unsigned long long)vm->run->fail_entry.hardware_entry_failure_reason);
                vm->running = 0;
                break;

            case KVM_EXIT_INTERNAL_ERROR:
                KVM_ERR("KVM_EXIT_INTERNAL_ERROR: suberror=%u",
                        vm->run->internal.suberror);
                vm->running = 0;
                break;

            default:
                /* その他の exit reason は無視して実行継続 */
                break;
        }
    }

    KVM_LOG("vCPU thread exiting");
    return NULL;
}

/* ════════════════════════════════════════════════
   Phase 5 公開 API
   ════════════════════════════════════════════════ */

static void kvm_hybrid_init_once(void) {
    if (g_vm_inited) return;
    kvm_vm_init(&g_vm);

    if (!g_vm.use_software_fallback && g_vm.vcpu_fd >= 0) {
        g_vm.running = 1;
        pthread_create(&g_vm.vcpu_thread, NULL, vcpu_thread_fn, &g_vm);
        KVM_LOG("KVM vCPU thread launched");
    }
    g_vm_inited = 1;
}

/* KVMハイブリッドモード初期化 */
int linexe_kvm_init(void) {
    pthread_mutex_lock(&g_vm_lock);
    kvm_hybrid_init_once();
    pthread_mutex_unlock(&g_vm_lock);
    return (g_vm.ipc != NULL) ? 0 : -1;
}

/* アンチチートドライバのロード要求
 * driver_path: .sys ファイルのパス
 * game_name:   ゲーム名（ログ用）
 * 戻値: 0=成功（またはフォールバック成功）
 */
int linexe_ac_load_driver(const char* driver_path, const char* game_name) {
    pthread_mutex_lock(&g_vm_lock);

    if (!g_vm.ipc) {
        pthread_mutex_unlock(&g_vm_lock);
        return -1;
    }

    if (game_name)
        strncpy((char*)g_vm.ipc->game_name, game_name,
                sizeof(g_vm.ipc->game_name) - 1);

    if (g_vm.use_software_fallback) {
        /* ソフトウェアモード: ドライバをロードした振りをする */
        if (driver_path) {
            /* ファイル名だけ取り出す */
            const char* base = strrchr(driver_path, '/');
            base = base ? base + 1 : driver_path;
            strncpy((char*)g_vm.ipc->driver_name, base,
                    sizeof(g_vm.ipc->driver_name) - 1);
        }
        g_vm.ipc->ac_driver_state = 2;
        g_vm.ipc->integrity_check = 1;
        KVM_LOG("Software mode: AC driver '%s' simulated for '%s'",
                g_vm.ipc->driver_name, g_vm.ipc->game_name);
        pthread_mutex_unlock(&g_vm_lock);
        return 0;
    }

    /* KVMモード: ゲストにドライバロードを要求
     * 実際の実装ではゲストメモリにドライバパスを書いて
     * hypercall でゲストを起こす必要がある（Phase 5.1 以降） */
    KVM_LOG("KVM mode: requesting driver load '%s' for '%s'",
            driver_path ? driver_path : "(null)", game_name ? game_name : "?");

    /* 暫定: IPCを介して状態を直接設定 */
    g_vm.ipc->ac_driver_state = 1; /* 初期化中 */

    /* 少し待ってからゲストが応答するのを待つ */
    for (int i = 0; i < 10; i++) {
        usleep(10000); /* 10ms */
        if (g_vm.ipc->ac_driver_state == 2) break;
    }

    if (g_vm.ipc->ac_driver_state != 2) {
        /* タイムアウト: フォールバックとして成功を偽装 */
        g_vm.ipc->ac_driver_state = 2;
        g_vm.ipc->integrity_check = 1;
        KVM_LOG("Driver load timeout, spoofing success");
    }

    pthread_mutex_unlock(&g_vm_lock);
    return 0;
}

/* 整合性チェックが通過しているか確認 */
int linexe_ac_integrity_ok(void) {
    if (!g_vm.ipc) return 0;
    return (g_vm.ipc->integrity_check == 1) ? 1 : 0;
}

/* アンチチートドライバの状態文字列 */
const char* linexe_ac_driver_status(void) {
    if (!g_vm.ipc) return "not_initialized";
    switch (g_vm.ipc->ac_driver_state) {
        case 0: return "not_loaded";
        case 1: return "initializing";
        case 2: return "active";
        default: return "error";
    }
}

/* VM 状態のダンプ（デバッグ用） */
void linexe_kvm_dump_state(void) {
    KVM_LOG("=== KVM Hybrid State ===");
    KVM_LOG("  mode          : %s",
            g_vm.use_software_fallback ? "software" : "KVM");
    KVM_LOG("  driver        : %s",
            g_vm.ipc ? g_vm.ipc->driver_name : "(none)");
    KVM_LOG("  game          : %s",
            g_vm.ipc ? g_vm.ipc->game_name : "(none)");
    KVM_LOG("  ac_state      : %s", linexe_ac_driver_status());
    KVM_LOG("  integrity     : %s",
            linexe_ac_integrity_ok() ? "OK" : "FAIL");
    if (g_vm.ipc)
        KVM_LOG("  checks_done   : %u", g_vm.ipc->check_count);
}

/* KVM終了処理 */
void linexe_kvm_shutdown(void) {
    pthread_mutex_lock(&g_vm_lock);

    if (g_vm.running) {
        g_vm.running = 0;
        pthread_join(g_vm.vcpu_thread, NULL);
    }

    if (g_vm.run && g_vm.run != MAP_FAILED)
        munmap(g_vm.run, g_vm.run_size);
    if (g_vm.vcpu_fd >= 0) close(g_vm.vcpu_fd);
    if (g_vm.vm_fd >= 0)   close(g_vm.vm_fd);
    if (g_vm.kvm_fd >= 0)  close(g_vm.kvm_fd);

    if (g_vm.guest_mem && g_vm.guest_mem != MAP_FAILED) {
        if (g_vm.use_software_fallback)
            free(g_vm.ipc); /* ソフトウェアモードは独立確保 */
        munmap(g_vm.guest_mem, g_vm.guest_mem_size);
    } else if (g_vm.use_software_fallback && g_vm.ipc) {
        free(g_vm.ipc);
    }

    memset(&g_vm, 0, sizeof(g_vm));
    g_vm.kvm_fd  = -1;
    g_vm.vm_fd   = -1;
    g_vm.vcpu_fd = -1;

    g_vm_inited = 0;
    KVM_LOG("KVM hybrid shutdown complete");
    pthread_mutex_unlock(&g_vm_lock);
}

/* ════════════════════════════════════════════════
   アンチチートAPIフック（Phase 5 LD_PRELOAD追加分）
   ════════════════════════════════════════════════
 *
 * ゲームがアンチチートSDKを呼ぶ典型的なAPIを偽装する。
 * EasyAntiCheat / BattlEye のユーザーランドAPIを模倣。
 */

/* EasyAntiCheat 相当の偽API */
typedef enum {
    EAC_STATUS_INVALID    = 0,
    EAC_STATUS_LOADING    = 1,
    EAC_STATUS_CONNECTED  = 2,
    EAC_STATUS_CHECKING   = 3,
    EAC_STATUS_GOOD       = 4,
} EacStatus;

EacStatus EOS_AntiCheatClient_GetStatus(void) {
    linexe_kvm_init();
    EacStatus s = linexe_ac_integrity_ok() ? EAC_STATUS_GOOD : EAC_STATUS_LOADING;
    KVM_LOG("EOS_AntiCheatClient_GetStatus -> %d", s);
    return s;
}

/* BattlEye 相当の偽API */
int BEClient_GetStatus(void) {
    linexe_kvm_init();
    int ok = linexe_ac_integrity_ok();
    KVM_LOG("BEClient_GetStatus -> %d", ok);
    return ok; /* 1 = OK */
}

/* Vanguard 相当の偽API（kernel driver report） */
int vgk_is_running(void) {
    linexe_kvm_init();
    KVM_LOG("vgk_is_running -> 1 (spoofed)");
    return 1; /* 動いているように見せる */
}

/* nProtect GameGuard 相当 */
int GameGuard_IsOK(void) {
    linexe_kvm_init();
    KVM_LOG("GameGuard_IsOK -> 1 (spoofed)");
    return 1;
}
