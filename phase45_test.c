/*
 * Linexe - Phase 4 + 5 完全テストスイート
 * Licensed under Apache License 2.0
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "dx_types.h"

/* Phase 4 関数 */
extern int  dxbc_parse(const void*, size_t, void*);
extern int  dxbc_to_spirv(const void*, size_t, void**, size_t*);
extern void shader_cache_stats(void);

/* Phase 4.2 */
extern void linexe_dx11_blend_to_vk(const D3D11_BLEND_DESC*, void*, int);
extern void linexe_dx11_depth_to_vk(const D3D11_DEPTH_STENCIL_DESC*, void*);
extern void linexe_dx11_raster_to_vk(const D3D11_RASTERIZER_DESC*, void*);
extern uint64_t linexe_get_or_create_renderpass(uint64_t,void*,uint32_t,uint32_t,uint32_t);

/* Phase 4.3 */
extern int  linexe_swapchain_init(const DXGI_SWAP_CHAIN_DESC*,uint64_t,uint64_t,void*);
extern void linexe_swapchain_info(uint32_t*,uint32_t*,int*,int*);

/* Phase 5 */
extern int         linexe_kvm_init(void);
extern int         linexe_ac_load_driver(const char*, const char*);
extern int         linexe_ac_integrity_ok(void);
extern const char* linexe_ac_driver_status(void);
extern void        linexe_kvm_dump_state(void);
extern void        linexe_kvm_shutdown(void);

static int g_pass=0, g_fail=0, g_skip=0;
#define TEST(n,c) do{if(c){printf("  PASS  %s\n",n);g_pass++;}else{printf("  FAIL  %s (line %d)\n",n,__LINE__);g_fail++;}}while(0)
#define SKIP(n)   do{printf("  SKIP  %s\n",n);g_skip++;}while(0)
#define SECTION(s) printf("\n[%s]\n",s)

/* ════════════════════════════════════════════════
   TEST 1: DXBC パーサー
   ════════════════════════════════════════════════ */
typedef struct {
    int valid; uint16_t shader_type; uint8_t version_major; uint8_t version_minor;
    uint32_t instruction_count; uint32_t temp_register_count;
    uint32_t input_count; uint32_t output_count;
    uint32_t cb_count; uint32_t texture_count; uint32_t sampler_count;
    const uint8_t* shdr_data; uint32_t shdr_size;
} DxbcInfo;

static void test_dxbc_parser(void) {
    SECTION("DXBC パーサー");

    /* 最小 DXBC ブロブ（手動構築）
     * magic=DXBC, checksum=zeros, one=1, total=100, chunks=1
     * chunk[0] offset = sizeof(header) + 4 = 28
     * chunk: fourcc=SHDR, size=12
     *   version_token: type=FFFE(VS) major=4 minor=0 → 0xFFFE0040
     *   total_dwords=3
     */
    /* DxbcHeader(32) + offset[0](4) + DxbcChunk(8) + SHDR(12) = 56 bytes */
    static const uint8_t fake_dxbc[] = {
        /* DxbcHeader (32 bytes) */
        0x44,0x58,0x42,0x43,               /* magic DXBC */
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* checksum (16 bytes) */
        0x01,0x00,0x00,0x00,              /* one=1 */
        0x38,0x00,0x00,0x00,              /* total_size=56 (sizeof this array) */
        0x01,0x00,0x00,0x00,              /* chunk_count=1 */
        /* chunk_offsets[0] = 36 = 0x24 (offset from start of file) */
        0x24,0x00,0x00,0x00,
        /* DxbcChunk at byte 36 */
        0x53,0x48,0x44,0x52,              /* fourcc = SHDR */
        0x0C,0x00,0x00,0x00,              /* chunk data size = 12 */
        /* SHDR data (12 bytes): version_token + dword_count + nop */
        0x40,0x00,0xFE,0xFF,              /* VS 4.0: type=0xFFFE, major=4, minor=0 */
        0x03,0x00,0x00,0x00,              /* 3 dwords total */
        0x00,0x00,0x00,0x00,              /* nop */
    };

    DxbcInfo info;
    int r = dxbc_parse(fake_dxbc, sizeof(fake_dxbc), &info);
    TEST("正常DXBC解析成功", r == 0 && info.valid);
    TEST("シェーダータイプ VS (0xFFFE)", info.shader_type == 0xFFFE);
    TEST("SHDRデータポインタ設定", info.shdr_data != NULL);

    /* 不正 DXBC */
    static const uint8_t bad_dxbc[] = {0xDE,0xAD,0xBE,0xEF};
    memset(&info, 0, sizeof(info));
    r = dxbc_parse(bad_dxbc, sizeof(bad_dxbc), &info);
    TEST("不正マジックは解析失敗", r != 0);

    /* NULL */
    r = dxbc_parse(NULL, 0, &info);
    TEST("NULL入力は-1を返す", r == -1);

    /* サイズ不足 */
    r = dxbc_parse(fake_dxbc, 4, &info);
    TEST("サイズ不足は失敗", r != 0);
}

/* ════════════════════════════════════════════════
   TEST 2: DXBC→SPIR-V 変換 + キャッシュ
   ════════════════════════════════════════════════ */
static void test_shader_translate(void) {
    SECTION("DXBC → SPIR-V 変換 + キャッシュ");

    /* 32+4+8+16=60=0x3C bytes */
    static const uint8_t fake_vs[] = {
        0x44,0x58,0x42,0x43,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x01,0x00,0x00,0x00,0x3C,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
        0x24,0x00,0x00,0x00,
        0x53,0x48,0x44,0x52,0x10,0x00,0x00,0x00,
        0x40,0x00,0xFE,0xFF, /* VS 4.0 */
        0x04,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };

    void* spv = NULL; size_t sz = 0;
    int r = dxbc_to_spirv(fake_vs, sizeof(fake_vs), &spv, &sz);
    TEST("VS→SPIR-V変換成功", r == 0 && spv != NULL && sz >= 4);

    if (spv && sz >= 4) {
        uint32_t magic; memcpy(&magic, spv, 4);
        TEST("SPIR-Vマジック正しい (0x07230203)", magic == 0x07230203);
    }

    /* 2回目はキャッシュヒット */
    void* spv2 = NULL; size_t sz2 = 0;
    r = dxbc_to_spirv(fake_vs, sizeof(fake_vs), &spv2, &sz2);
    TEST("2回目はキャッシュHIT", r == 0 && sz2 == sz);
    TEST("キャッシュ内容が同一", spv2 && sz2 == sz && memcmp(spv, spv2, sz) == 0);

    free(spv); free(spv2);
    shader_cache_stats();

    /* PS (0xFFFF) */
    static const uint8_t fake_ps[] = {
        0x44,0x58,0x42,0x43,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x01,0x00,0x00,0x00,0x3C,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
        0x24,0x00,0x00,0x00,
        0x53,0x48,0x44,0x52,0x10,0x00,0x00,0x00,
        0x40,0x00,0xFF,0xFF, /* PS 4.0 */
        0x04,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };
    void* pspv = NULL; size_t psz = 0;
    r = dxbc_to_spirv(fake_ps, sizeof(fake_ps), &pspv, &psz);
    TEST("PS→SPIR-V変換成功", r == 0 && pspv != NULL && psz >= 4);
    if (pspv && psz >= 4) {
        uint32_t magic; memcpy(&magic, pspv, 4);
        TEST("PS SPIR-Vマジック正しい", magic == 0x07230203);
    }
    free(pspv);

    /* NULL入力 */
    void* nspv = NULL; size_t nsz = 0;
    r = dxbc_to_spirv(NULL, 0, &nspv, &nsz);
    TEST("NULL入力は-1を返す", r == -1 && nspv == NULL);
}

/* ════════════════════════════════════════════════
   TEST 3: ブレンドステート変換
   ════════════════════════════════════════════════ */
typedef struct {
    uint32_t blendEnable,srcColor,dstColor,colorOp,srcAlpha,dstAlpha,alphaOp,writeMask;
} VkCBA;

static void test_blend_state(void) {
    SECTION("D3D11 ブレンドステート → Vulkan");

    D3D11_BLEND_DESC desc = {0};

    /* アルファブレンド有効 */
    desc.RenderTarget[0].BlendEnable    = 1;
    desc.RenderTarget[0].SrcBlend       = D3D11_BLEND_SRC_ALPHA;
    desc.RenderTarget[0].DestBlend      = D3D11_BLEND_INV_SRC_ALPHA;
    desc.RenderTarget[0].BlendOp        = D3D11_BLEND_OP_ADD;
    desc.RenderTarget[0].SrcBlendAlpha  = D3D11_BLEND_ONE;
    desc.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_ZERO;
    desc.RenderTarget[0].BlendOpAlpha   = D3D11_BLEND_OP_ADD;
    desc.RenderTarget[0].RenderTargetWriteMask = 0xF;

    VkCBA vk = {0};
    linexe_dx11_blend_to_vk(&desc, &vk, 0);
    TEST("BlendEnable=1", vk.blendEnable == 1);
    TEST("SrcColor=SRC_ALPHA(6)", vk.srcColor == 6);
    TEST("DstColor=ONE_MINUS_SRC_ALPHA(7)", vk.dstColor == 7);
    TEST("ColorOp=ADD(0)", vk.colorOp == 0);
    TEST("WriteMask=0xF", vk.writeMask == 0xF);

    /* ブレンド無効 */
    D3D11_BLEND_DESC desc2 = {0};
    desc2.RenderTarget[0].BlendEnable = 0;
    desc2.RenderTarget[0].RenderTargetWriteMask = 0xF;
    VkCBA vk2 = {0};
    linexe_dx11_blend_to_vk(&desc2, &vk2, 0);
    TEST("BlendEnable=0", vk2.blendEnable == 0);

    /* NULL安全 */
    linexe_dx11_blend_to_vk(NULL, &vk, 0);
    linexe_dx11_blend_to_vk(&desc, NULL, 0);
    TEST("NULL安全（クラッシュなし）", 1);
}

/* ════════════════════════════════════════════════
   TEST 4: 深度ステート変換
   ════════════════════════════════════════════════ */
typedef struct { uint32_t dte,dwe,dcmp,dbte,ste; } VkDSS;

static void test_depth_state(void) {
    SECTION("D3D11 深度ステート → Vulkan");

    D3D11_DEPTH_STENCIL_DESC d = {0};
    d.DepthEnable    = 1;
    d.DepthWriteMask = 1;
    d.DepthFunc      = 2; /* D3D11_COMPARISON_LESS */
    d.StencilEnable  = 0;

    VkDSS vk = {0};
    linexe_dx11_depth_to_vk(&d, &vk);
    TEST("DepthTestEnable=1",  vk.dte == 1);
    TEST("DepthWriteEnable=1", vk.dwe == 1);
    TEST("DepthCompare=LESS(1)", vk.dcmp == 1);
    TEST("StencilEnable=0",   vk.ste == 0);

    /* ALWAYS */
    D3D11_DEPTH_STENCIL_DESC d2 = {0};
    d2.DepthEnable = 0;
    VkDSS vk2 = {0};
    linexe_dx11_depth_to_vk(&d2, &vk2);
    TEST("DepthDisabled", vk2.dte == 0);

    linexe_dx11_depth_to_vk(NULL, &vk);
    TEST("NULL安全", 1);
}

/* ════════════════════════════════════════════════
   TEST 5: ラスタライザーステート変換
   ════════════════════════════════════════════════ */
typedef struct {
    uint32_t dce,rde,pm,cull,ff,dbe;
    float dbc,dbcl,dbsf,lw;
} VkRSS;

static void test_raster_state(void) {
    SECTION("D3D11 ラスタライザー → Vulkan");

    D3D11_RASTERIZER_DESC d = {0};
    d.FillMode              = 3; /* SOLID */
    d.CullMode              = 3; /* BACK */
    d.FrontCounterClockwise = 0;
    d.DepthBias             = 0;
    d.DepthClipEnable       = 1;

    VkRSS vk = {0};
    linexe_dx11_raster_to_vk(&d, &vk);
    TEST("FillMode SOLID -> polygonMode=0", vk.pm == 0);
    TEST("CullMode BACK -> 2", vk.cull == 2);
    TEST("FrontFace CW -> 1",  vk.ff == 1);
    TEST("LineWidth=1.0", vk.lw == 1.0f);

    /* WIREFRAME */
    D3D11_RASTERIZER_DESC d2 = {0};
    d2.FillMode = 2; d2.CullMode = 1; /* NONE */
    VkRSS vk2 = {0};
    linexe_dx11_raster_to_vk(&d2, &vk2);
    TEST("FillMode WIREFRAME -> polygonMode=1", vk2.pm == 1);
    TEST("CullMode NONE -> 0", vk2.cull == 0);

    linexe_dx11_raster_to_vk(NULL, &vk);
    TEST("NULL安全", 1);
}

/* ════════════════════════════════════════════════
   TEST 6: SwapChain 初期化
   ════════════════════════════════════════════════ */
static void test_swapchain(void) {
    SECTION("SwapChain 初期化 (Phase 4.3)");

    DXGI_SWAP_CHAIN_DESC desc = {0};
    desc.BufferDesc.Width  = 1280;
    desc.BufferDesc.Height = 720;
    desc.BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.BufferCount = 2;
    desc.Windowed = 1;

    int r = linexe_swapchain_init(&desc, 0, 0, NULL);
    TEST("SwapChain init成功（headless）", r == 0);

    uint32_t w=0,h=0; int fmt=0,ready=0;
    linexe_swapchain_info(&w, &h, &fmt, &ready);
    TEST("幅 1280", w == 1280);
    TEST("高さ 720", h == 720);
    TEST("フォーマット設定済み (VK=44 BGRA8)", fmt == 44);
    TEST("ready フラグ", ready);

    /* NULL記述子 */
    r = linexe_swapchain_init(NULL, 0, 0, NULL);
    TEST("NULL記述子は-1を返す", r == -1);

    /* デフォルトサイズ（0x0） */
    DXGI_SWAP_CHAIN_DESC d2 = {0};
    d2.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    r = linexe_swapchain_init(&d2, 0, 0, NULL);
    TEST("0x0はデフォルトサイズに丸める", r == 0);
    linexe_swapchain_info(&w, &h, NULL, NULL);
    TEST("デフォルト幅 >= 800", w >= 800);
    TEST("デフォルト高さ >= 600", h >= 600);
}

/* ════════════════════════════════════════════════
   TEST 7: KVM ハイブリッド (Phase 5)
   ════════════════════════════════════════════════ */
static void test_kvm_hybrid(void) {
    SECTION("KVM ハイブリッド アンチチート (Phase 5)");

    /* 初期化 */
    int r = linexe_kvm_init();
    TEST("KVM init成功（KVM不在時はフォールバック）", r == 0);

    /* ドライバロード */
    r = linexe_ac_load_driver("/path/to/fake_anticheat.sys", "TestGame");
    TEST("ドライバロード成功", r == 0);

    /* 状態確認 */
    const char* status = linexe_ac_driver_status();
    TEST("ドライバ状態がactive", strcmp(status, "active") == 0);
    TEST("整合性チェック通過", linexe_ac_integrity_ok() == 1);

    /* 状態ダンプ */
    linexe_kvm_dump_state();

    /* 2回目のロードも成功 */
    r = linexe_ac_load_driver(NULL, "AnotherGame");
    TEST("2回目ドライバロード成功", r == 0);

    /* フック関数 */
    extern int EOS_AntiCheatClient_GetStatus(void);
    extern int BEClient_GetStatus(void);
    extern int vgk_is_running(void);
    extern int GameGuard_IsOK(void);

    TEST("EAC GetStatus = 4 (GOOD)", EOS_AntiCheatClient_GetStatus() == 4);
    TEST("BattlEye GetStatus = 1", BEClient_GetStatus() == 1);
    TEST("Vanguard is_running = 1", vgk_is_running() == 1);
    TEST("GameGuard IsOK = 1",      GameGuard_IsOK() == 1);

    linexe_kvm_shutdown();
    TEST("シャットダウン後も再初期化可能", linexe_kvm_init() == 0);
}

/* ════════════════════════════════════════════════
   TEST 8: IPC 共有メモリ整合性
   ════════════════════════════════════════════════ */
static void test_ipc_integrity(void) {
    SECTION("IPC 共有メモリ整合性");

    /* linexe_kvm_init が呼ばれていることを前提 */
    linexe_kvm_init();

    /* ドライバ状態の遷移テスト */
    linexe_ac_load_driver("/fake/eac.sys", "GameA");
    TEST("GameA: active", strcmp(linexe_ac_driver_status(), "active") == 0);
    TEST("GameA: integrity_ok", linexe_ac_integrity_ok());

    linexe_ac_load_driver("/fake/battleye.sys", "GameB");
    TEST("GameB: active", strcmp(linexe_ac_driver_status(), "active") == 0);
    TEST("GameB: integrity_ok", linexe_ac_integrity_ok());

    /* 並行チェック（複数スレッドからの呼び出しを模擬） */
    int ok = 1;
    for (int i = 0; i < 100; i++) {
        if (!linexe_ac_integrity_ok()) { ok = 0; break; }
    }
    TEST("100回連続整合性チェック全通過", ok);
}

/* ════════════════════════════════════════════════
   メイン
   ════════════════════════════════════════════════ */
int main(void) {
    printf("╔════════════════════════════════════════════╗\n");
    printf("║  Linexe Phase 4+5 Complete Test Suite      ║\n");
    printf("╚════════════════════════════════════════════╝\n");

    struct timespec t0,t1;
    clock_gettime(CLOCK_MONOTONIC,&t0);

    test_dxbc_parser();
    test_shader_translate();
    test_blend_state();
    test_depth_state();
    test_raster_state();
    test_swapchain();
    test_kvm_hybrid();
    test_ipc_integrity();

    clock_gettime(CLOCK_MONOTONIC,&t1);
    double el=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

    printf("\n══════════════════════════════════════════════\n");
    printf("  PASS: %d   FAIL: %d   SKIP: %d   TIME: %.2fs\n",
           g_pass,g_fail,g_skip,el);
    printf("══════════════════════════════════════════════\n");
    return g_fail>0?1:0;
}
