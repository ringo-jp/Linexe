/*
 * Linexe - Phase 4 Test Suite (DirectX → Vulkan)
 * Licensed under Apache License 2.0
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <dlfcn.h>
#include <time.h>

#include "dx_types.h"

/* フック関数の前方宣言 */
HRESULT D3D11CreateDevice(void*,unsigned int,void*,unsigned int,
    const D3D_FEATURE_LEVEL*,unsigned int,unsigned int,
    ID3D11Device**,D3D_FEATURE_LEVEL*,void**);
HRESULT D3D11CreateDeviceAndSwapChain(void*,unsigned int,void*,unsigned int,
    const D3D_FEATURE_LEVEL*,unsigned int,unsigned int,
    const DXGI_SWAP_CHAIN_DESC*,IDXGISwapChain**,ID3D11Device**,
    D3D_FEATURE_LEVEL*,void**);

/* CreateBuffer/CreateTexture2D は LxD3D11Device の vtbl 経由 */
typedef HRESULT (*PFN_CreateBuffer_t)(void*,const D3D11_BUFFER_DESC*,
    const D3D11_SUBRESOURCE_DATA*,ID3D11Buffer**);
typedef HRESULT (*PFN_CreateTexture2D_t)(void*,const D3D11_TEXTURE2D_DESC*,
    const D3D11_SUBRESOURCE_DATA*,ID3D11Texture2D**);

static int g_pass=0,g_fail=0;
#define TEST(n,c) do{if(c){printf("  PASS  %s\n",n);g_pass++;}else{printf("  FAIL  %s (line %d)\n",n,__LINE__);g_fail++;}}while(0)
#define SECTION(s) printf("\n[%s]\n",s)

/* ════════════════════════════════════════════════
   TEST 1: DXGI Format 変換テーブル
   ════════════════════════════════════════════════ */
static void test_format_table(void) {
    SECTION("DXGI Format 変換テーブル");

    TEST("テーブルサイズ24以上", DX_FORMAT_TABLE_LEN >= 24);

    /* 重要フォーマットの変換確認 */
    TEST("RGBA8_UNORM -> VK_FORMAT_R8G8B8A8_UNORM(37)",
         dxgi_to_vk_format(DXGI_FORMAT_R8G8B8A8_UNORM) == 37);
    TEST("D32_FLOAT -> VK_FORMAT_D32_SFLOAT(126)",
         dxgi_to_vk_format(DXGI_FORMAT_D32_FLOAT) == 126);
    TEST("RGBA32_FLOAT -> VK_FORMAT_R32G32B32A32_SFLOAT(109)",
         dxgi_to_vk_format(DXGI_FORMAT_R32G32B32A32_FLOAT) == 109);
    TEST("BGRA8_UNORM -> VK_FORMAT_B8G8R8A8_UNORM(44)",
         dxgi_to_vk_format(DXGI_FORMAT_B8G8R8A8_UNORM) == 44);
    TEST("BC1_UNORM -> VK_FORMAT_BC1(131)",
         dxgi_to_vk_format(DXGI_FORMAT_BC1_UNORM) == 131);
    TEST("BC7_UNORM -> VK_FORMAT_BC7(145)",
         dxgi_to_vk_format(DXGI_FORMAT_BC7_UNORM) == 145);
    TEST("D24_S8 -> VK_FORMAT_D24_UNORM_S8_UINT(129)",
         dxgi_to_vk_format(DXGI_FORMAT_D24_UNORM_S8_UINT) == 129);
    TEST("UNKNOWN -> VK_FORMAT_UNDEFINED(0)",
         dxgi_to_vk_format(DXGI_FORMAT_UNKNOWN) == 0);
    TEST("未知フォーマット -> UNDEFINED",
         dxgi_to_vk_format((DXGI_FORMAT)9999) == 0);

    /* フォーマット名テスト */
    TEST("フォーマット名 RGBA8_UNORM",
         strcmp(dxgi_format_name(DXGI_FORMAT_R8G8B8A8_UNORM), "RGBA8_UNORM")==0);
    TEST("フォーマット名 UNKNOWN",
         strcmp(dxgi_format_name(DXGI_FORMAT_UNKNOWN), "UNKNOWN")==0);

    /* 重複チェック */
    int dupes = 0;
    for (size_t i=0; i<DX_FORMAT_TABLE_LEN; i++)
        for (size_t j=i+1; j<DX_FORMAT_TABLE_LEN; j++)
            if (DX_FORMAT_TABLE[i].dx_fmt == DX_FORMAT_TABLE[j].dx_fmt
                && DX_FORMAT_TABLE[i].dx_fmt != DXGI_FORMAT_UNKNOWN) dupes++;
    TEST("DXGIフォーマット重複なし", dupes==0);
}

/* ════════════════════════════════════════════════
   TEST 2: D3D11CreateDevice フック
   ════════════════════════════════════════════════ */
static void test_create_device(void) {
    SECTION("D3D11CreateDevice フック");

    ID3D11Device* device = NULL;
    D3D_FEATURE_LEVEL fl_req[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL fl_out = 0;
    void* ctx = NULL;

    HRESULT hr = D3D11CreateDevice(NULL, 1, NULL, 0,
                                    fl_req, 2, 7,
                                    &device, &fl_out, &ctx);
    TEST("D3D11CreateDevice 成功", SUCCEEDED(hr));
    TEST("デバイスオブジェクト生成", device != NULL);
    TEST("FeatureLevel 返却", fl_out == D3D_FEATURE_LEVEL_11_0);
    TEST("lpVtbl 設定済み", device != NULL && *(const void**)device != NULL);

    if (device) {
        const IUnknownVtbl* vtbl = *(const IUnknownVtbl**)device;
        TEST("AddRef 関数ポインタ存在", vtbl->AddRef != NULL);
        TEST("Release 関数ポインタ存在", vtbl->Release != NULL);

        ULONG ref = vtbl->AddRef((IUnknown*)device);
        TEST("AddRef -> refcount 2", ref == 2);
        ref = vtbl->Release((IUnknown*)device);
        TEST("Release -> refcount 1", ref == 1);
        vtbl->Release((IUnknown*)device);
    }
}

/* ════════════════════════════════════════════════
   TEST 3: D3D11CreateDeviceAndSwapChain
   ════════════════════════════════════════════════ */
static void test_create_device_swapchain(void) {
    SECTION("D3D11CreateDeviceAndSwapChain");

    DXGI_SWAP_CHAIN_DESC scd = {0};
    scd.BufferDesc.Width  = 1280;
    scd.BufferDesc.Height = 720;
    scd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    scd.BufferCount = 2;
    scd.Windowed    = 1;

    IDXGISwapChain* sc = NULL;
    ID3D11Device*   dev = NULL;
    D3D_FEATURE_LEVEL fl = 0;

    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        NULL, 1, NULL, 0, NULL, 0, 7,
        &scd, &sc, &dev, &fl, NULL);

    TEST("D3D11CreateDeviceAndSwapChain 成功", SUCCEEDED(hr));
    TEST("SwapChainはPhase4.3で実装予定", sc == NULL);
    TEST("Device 生成", dev != NULL);

    if (dev) {
        const IUnknownVtbl* vtbl = *(const IUnknownVtbl**)dev;
        vtbl->Release((IUnknown*)dev);
    }
}

/* ════════════════════════════════════════════════
   TEST 4: CreateBuffer（Vulkanバックエンド）
   ════════════════════════════════════════════════ */
static void test_create_buffer(void) {
    SECTION("CreateBuffer (D3D11 -> VkBuffer)");

    ID3D11Device* device = NULL;
    D3D_FEATURE_LEVEL fl = 0;
    HRESULT hr = D3D11CreateDevice(NULL,1,NULL,0,NULL,0,7,&device,&fl,NULL);
    if (FAILED(hr) || !device) {
        printf("  SKIP  Vulkan not available\n");
        return;
    }

    /* vtbl経由でCreateBufferを呼ぶ（vtblの4番目のメソッド） */
    typedef struct { void* qi; void* ar; void* rel; PFN_CreateBuffer_t cb; } MinVtbl;
    const MinVtbl* vtbl = (const MinVtbl*)*(const void**)device;

    if (!vtbl->cb) {
        printf("  SKIP  CreateBuffer not in vtbl\n");
        goto cleanup;
    }

    /* 頂点バッファ */
    D3D11_BUFFER_DESC vb_desc = {
        .ByteWidth      = 1024,
        .Usage          = D3D11_USAGE_DEFAULT,
        .BindFlags      = D3D11_BIND_VERTEX_BUFFER,
        .CPUAccessFlags = 0,
    };
    float verts[] = {0.0f,0.5f,0.0f, -0.5f,-0.5f,0.0f, 0.5f,-0.5f,0.0f};
    D3D11_SUBRESOURCE_DATA init = {.pSysMem = verts};

    ID3D11Buffer* vbuf = NULL;
    hr = vtbl->cb(device, &vb_desc, &init, &vbuf);
    if (hr == E_FAIL) { printf("  SKIP  Vulkan GPU not available (expected in headless env)\n"); goto cleanup; }
    TEST("頂点バッファ生成成功", SUCCEEDED(hr) && vbuf != NULL);

    if (vbuf) {
        const IUnknownVtbl* bvtbl = *(const IUnknownVtbl**)vbuf;
        TEST("バッファのvtbl存在", bvtbl != NULL);
        bvtbl->Release((IUnknown*)vbuf);
    }

    /* 定数バッファ */
    D3D11_BUFFER_DESC cb_desc = {
        .ByteWidth      = 256, /* 256バイト境界 */
        .Usage          = D3D11_USAGE_DYNAMIC,
        .BindFlags      = D3D11_BIND_CONSTANT_BUFFER,
        .CPUAccessFlags = D3D11_CPU_ACCESS_WRITE,
    };
    ID3D11Buffer* cbuf = NULL;
    hr = vtbl->cb(device, &cb_desc, NULL, &cbuf);
    TEST("定数バッファ生成成功", SUCCEEDED(hr) && cbuf != NULL);
    if (cbuf) { const IUnknownVtbl* bvtbl=*(const IUnknownVtbl**)cbuf; bvtbl->Release((IUnknown*)cbuf); }

    /* NULL記述子エラーチェック */
    ID3D11Buffer* nbuf = NULL;
    hr = vtbl->cb(device, NULL, NULL, &nbuf);
    TEST("NULL記述子 -> E_INVALIDARG", hr == E_INVALIDARG && nbuf == NULL);

    /* 0バイトバッファは通常不正 */
    D3D11_BUFFER_DESC z_desc = {.ByteWidth=0,.BindFlags=D3D11_BIND_VERTEX_BUFFER};
    ID3D11Buffer* zbuf = NULL;
    hr = vtbl->cb(device, &z_desc, NULL, &zbuf);
    TEST("0バイトバッファは失敗またはサイズ1に丸める", FAILED(hr) || zbuf != NULL);
    if (zbuf && SUCCEEDED(hr)) { const IUnknownVtbl* bv=*(const IUnknownVtbl**)zbuf; bv->Release((IUnknown*)zbuf); }

cleanup:;
    const IUnknownVtbl* dvtbl = *(const IUnknownVtbl**)device;
    dvtbl->Release((IUnknown*)device);
}

/* ════════════════════════════════════════════════
   TEST 5: CreateTexture2D（Vulkanバックエンド）
   ════════════════════════════════════════════════ */
static void test_create_texture(void) {
    SECTION("CreateTexture2D (D3D11 -> VkImage)");

    ID3D11Device* device = NULL;
    D3D_FEATURE_LEVEL fl = 0;
    HRESULT hr = D3D11CreateDevice(NULL,1,NULL,0,NULL,0,7,&device,&fl,NULL);
    if (FAILED(hr)||!device){printf("  SKIP  Vulkan not available\n");return;}

    /* vtblのCreateTexture2Dはオフセット9（3 IUnknown + 5 stub + 1） */
    typedef struct { void* qi;void* ar;void* rel;void* cb;void* s[5];PFN_CreateTexture2D_t ct; } MinVtbl2;
    const MinVtbl2* vtbl = (const MinVtbl2*)*(const void**)device;

    if (!vtbl->ct) {
        printf("  SKIP  CreateTexture2D not available\n");
        goto done;
    }

    /* カラーテクスチャ */
    D3D11_TEXTURE2D_DESC td = {
        .Width=512,.Height=512,.MipLevels=1,.ArraySize=1,
        .Format=DXGI_FORMAT_R8G8B8A8_UNORM,
        .SampleDesc={1,0},
        .Usage=D3D11_USAGE_DEFAULT,
        .BindFlags=D3D11_BIND_SHADER_RESOURCE|D3D11_BIND_RENDER_TARGET,
    };
    ID3D11Texture2D* tex = NULL;
    hr = vtbl->ct(device, &td, NULL, &tex);
    if (hr == E_FAIL) { printf("  SKIP  Vulkan GPU not available (expected in headless env)\n"); goto done; }
    TEST("512x512 RGBA8テクスチャ生成", SUCCEEDED(hr) && tex != NULL);
    if(tex){const IUnknownVtbl* tv=*(const IUnknownVtbl**)tex;tv->Release((IUnknown*)tex);}

    /* 深度テクスチャ */
    D3D11_TEXTURE2D_DESC dd = {
        .Width=1920,.Height=1080,.MipLevels=1,.ArraySize=1,
        .Format=DXGI_FORMAT_D32_FLOAT,
        .SampleDesc={1,0},
        .Usage=D3D11_USAGE_DEFAULT,
        .BindFlags=D3D11_BIND_DEPTH_STENCIL,
    };
    ID3D11Texture2D* depth = NULL;
    hr = vtbl->ct(device, &dd, NULL, &depth);
    TEST("1920x1080 D32深度テクスチャ生成", SUCCEEDED(hr) && depth != NULL);
    if(depth){const IUnknownVtbl* tv=*(const IUnknownVtbl**)depth;tv->Release((IUnknown*)depth);}

    /* NULL記述子 */
    ID3D11Texture2D* ntex = NULL;
    hr = vtbl->ct(device, NULL, NULL, &ntex);
    TEST("NULL記述子 -> E_INVALIDARG", hr==E_INVALIDARG && ntex==NULL);

done:;
    const IUnknownVtbl* dv=*(const IUnknownVtbl**)device;
    dv->Release((IUnknown*)device);
}

/* ════════════════════════════════════════════════
   TEST 6: D3D11 型構造体サイズ検証
   ════════════════════════════════════════════════ */
static void test_struct_sizes(void) {
    SECTION("D3D11 構造体サイズ");

    /* 参考: Windows SDK の sizeof */
    TEST("D3D11_BUFFER_DESC = 24",      sizeof(D3D11_BUFFER_DESC)      == 24);
    TEST("D3D11_VIEWPORT    = 24",      sizeof(D3D11_VIEWPORT)         == 24);
    TEST("D3D11_MAPPED_SUBRESOURCE size >= 12", sizeof(D3D11_MAPPED_SUBRESOURCE) >= 12);
    /* TEXTURE2D_DESC は プラットフォームにより異なるため範囲チェック */
    TEST("D3D11_TEXTURE2D_DESC >= 44",  sizeof(D3D11_TEXTURE2D_DESC)   >= 44);
    TEST("D3D11_SAMPLER_DESC >= 52",    sizeof(D3D11_SAMPLER_DESC)     >= 52);
}

/* ════════════════════════════════════════════════
   メイン
   ════════════════════════════════════════════════ */
int main(void) {
    printf("╔════════════════════════════════════════════╗\n");
    printf("║  Linexe Phase 4 Test Suite (D3D11->Vulkan) ║\n");
    printf("╚════════════════════════════════════════════╝\n");

    struct timespec t0,t1;
    clock_gettime(CLOCK_MONOTONIC,&t0);

    test_format_table();
    test_struct_sizes();
    test_create_device();
    test_create_device_swapchain();
    test_create_buffer();
    test_create_texture();

    clock_gettime(CLOCK_MONOTONIC,&t1);
    double el=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

    printf("\n══════════════════════════════════════════════\n");
    printf("  PASS: %d   FAIL: %d   TIME: %.2fs\n",g_pass,g_fail,el);
    printf("══════════════════════════════════════════════\n");
    return g_fail>0?1:0;
}
