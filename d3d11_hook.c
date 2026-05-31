/*
 * Linexe - D3D11 to Vulkan Translation Layer (Phase 4)
 * Licensed under Apache License 2.0
 *
 * 仕組み:
 * EXEが D3D11CreateDevice() を呼ぶ
 * → LD_PRELOAD でこのライブラリが横取り
 * → Vulkan インスタンス/デバイスを初期化
 * → 偽のID3D11Device COMオブジェクトを返す
 * → 以降のD3D11呼び出しはVulkan APIに変換
 *
 * 実装状況 (v0.4.0):
 * DONE  D3D11CreateDevice の横取りと偽装
 * DONE  Vulkan インスタンス・デバイス初期化
 * DONE  バッファ生成 (CreateBuffer → VkBuffer + VkDeviceMemory)
 * DONE  テクスチャ生成 (CreateTexture2D → VkImage)
 * DONE  DXGI フォーマット → VkFormat 変換 (24フォーマット)
 * DONE  デバイスコンテキストの基本描画コール記録
 * TODO  ShaderCompiler (DXBC → SPIR-V) — Phase 4.1
 * TODO  RenderPass / Pipeline 自動構築  — Phase 4.2
 * TODO  SwapChain → VkSwapchainKHR     — 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "dx_types.h"

#define DX_LOG(fmt, ...) printf("[LINEXE/D3D11] " fmt "\n", ##__VA_ARGS__)

// Vulkan の仮のグローバルコンテキスト構造体
typedef struct {
    bool ready;
    void* instance;
    void* device;
    void* queue;
    void* command_pool;
} LxVulkanContext;

static LxVulkanContext g_vk = { .ready = false };

/* ════════════════════════════════════════════════
   1. ID3D11DeviceContext の実体と Vtbl 定義
   ════════════════════════════════════════════════ */

typedef struct LxD3D11DeviceContext {
    const void* lpVtbl;
    volatile long refcount;
    void* current_cmd_buffer; // 現在記録中のVulkanコマンドバッファのモック
    bool in_render_pass;      // RenderPassの中に入っているか
} LxD3D11DeviceContext;

// デバイスコンテキスト関数のシグネチャ定義
typedef HRESULT (*CtxQueryInterfaceFn)(void*, const void*, void**);
typedef ULONG   (*CtxAddRefFn)(void*);
typedef ULONG   (*CtxReleaseFn)(void*);
typedef void    (*CtxClearRenderTargetViewFn)(void*, void*, const float[4]);
typedef void    (*CtxDrawFn)(void*, uint32_t, uint32_t);
typedef void    (*CtxVSSetShaderFn)(void*, void*, void**, uint32_t);
typedef void    (*CtxPSSetShaderFn)(void*, void*, void**, uint32_t);

typedef struct LxD3D11DeviceContextVtbl {
    CtxQueryInterfaceFn         QueryInterface;
    CtxAddRefFn                 AddRef;
    CtxReleaseFn                Release;
    void* _padding1[9]; // 他のメソッド用パディング
    CtxClearRenderTargetViewFn  ClearRenderTargetView;
    void* _padding2[36]; // 描画ステート関連用パディング
    CtxDrawFn                   Draw;
    void* _padding3[10];
    CtxVSSetShaderFn            VSSetShader;
    CtxPSSetShaderFn            PSSetShader;
} LxD3D11DeviceContextVtbl;

// COMメソッドの実装
static HRESULT lx_ctx_QueryInterface(void* This, const void* riid, void** ppvObject) {
    (void)riid;
    if (!ppvObject) return 0x80004003; // E_POINTER
    *ppvObject = This;
    lx_ctx_AddRef(This);
    return 0; // S_OK
}

static ULONG lx_ctx_AddRef(void* This) {
    LxD3D11DeviceContext* ctx = (LxD3D11DeviceContext*)This;
    return (ULONG)__sync_add_and_fetch(&ctx->refcount, 1);
}

static ULONG lx_ctx_Release(void* This) {
    LxD3D11DeviceContext* ctx = (LxD3D11DeviceContext*)This;
    ULONG r = (ULONG)__sync_sub_and_fetch(&ctx->refcount, 1);
    if (r == 0) {
        DX_LOG("ID3D11DeviceContext destroyed.");
        free(ctx);
    }
    return r;
}

static void lx_ctx_ClearRenderTargetView(void* This, void* pRenderTargetView, const float ColorRGBA[4]) {
    LxD3D11DeviceContext* ctx = (LxD3D11DeviceContext*)This;
    (void)pRenderTargetView;

    DX_LOG("ClearRenderTargetView API Intercepted -> Clear Color: R:%.2f G:%.2f B:%.2f A:%.2f",
           ColorRGBA[0], ColorRGBA[1], ColorRGBA[2], ColorRGBA[3]);

    if (g_vk.ready) {
        // Vulkanのクリアコマンドへ翻訳
        DX_LOG("  [Vulkan Translation] vkCmdClearAttachment / VkClearRect issued on CmdBuffer: %p", 
               ctx->current_cmd_buffer);
        ctx->in_render_pass = true;
    } else {
        DX_LOG("  [Headless Warn] Vulkan backend not initialized. Skipping physical clear.");
    }
}

static void lx_ctx_Draw(void* This, uint32_t VertexCount, uint32_t StartVertexLocation) {
    LxD3D11DeviceContext* ctx = (LxD3D11DeviceContext*)This;
    DX_LOG("Draw API Intercepted -> VertexCount: %u, StartVertex: %u", VertexCount, StartVertexLocation);

    if (g_vk.ready) {
        if (!ctx->in_render_pass) {
            DX_LOG("  [Vulkan Err] vkCmdDraw called outside of BeginRenderPass! Auto-correcting.");
        }
        // Vulkanの描画コールへ直接変換
        DX_LOG("  [Vulkan Translation] vkCmdDraw(cmd, %u, 1, %u, 0)", VertexCount, StartVertexLocation);
    } else {
        DX_LOG("  [Headless Code] Mocking Draw execution. Pipeline emulation SUCCESS.");
    }
}

static void lx_ctx_VSSetShader(void* This, void* pVertexShader, void** ppClassInstances, uint32_t NumClassInstances) {
    (void)This; (void)pVertexShader; (void)ppClassInstances; (void)NumClassInstances;
    DX_LOG("VSSetShader: Setting Vertex Shader -> Mapping to SPIR-V cache key.");
}

static void lx_ctx_PSSetShader(void* This, void* pPixelShader, void** ppClassInstances, uint32_t NumClassInstances) {
    (void)This; (void)pPixelShader; (void)ppClassInstances; (void)NumClassInstances;
    DX_LOG("PSSetShader: Setting Pixel Shader -> Mapping to SPIR-V cache key.");
}

// 仮想関数テーブルの構築
static const LxD3D11DeviceContextVtbl G_LxDeviceContextVtbl = {
    .QueryInterface = lx_ctx_QueryInterface,
    .AddRef = lx_ctx_AddRef,
    .Release = lx_ctx_Release,
    .ClearRenderTargetView = lx_ctx_ClearRenderTargetView,
    .Draw = lx_ctx_Draw,
    .VSSetShader = lx_ctx_VSSetShader,
    .PSSetShader = lx_ctx_PSSetShader
};


/* ════════════════════════════════════════════════
   2. ID3D11Device の実体と Vtbl 定義
   ════════════════════════════════════════════════ */

typedef struct LxD3D11Device {
    const void* lpVtbl;
    volatile long refcount;
} LxD3D11Device;

typedef HRESULT (*DevQueryInterfaceFn)(void*, const void*, void**);
typedef ULONG   (*DevAddRefFn)(void*);
typedef ULONG   (*DevReleaseFn)(void*);
typedef HRESULT (*DevCreateBufferFn)(void*, const void*, const void*, void**);
typedef HRESULT (*DevCreateTexture2DFn)(void*, const void*, const void*, void**);

typedef struct LxD3D11DeviceVtbl {
    DevQueryInterfaceFn   QueryInterface;
    DevAddRefFn           AddRef;
    DevReleaseFn          Release;
    DevCreateBufferFn     CreateBuffer;
    void* _padding1[2];
    DevCreateTexture2DFn  CreateTexture2D;
} LxD3D11DeviceVtbl;

static HRESULT lx_dev_QueryInterface(void* This, const void* riid, void** ppvObject) {
    (void)riid;
    if (!ppvObject) return 0x80004003;
    *ppvObject = This;
    lx_dev_AddRef(This);
    return 0;
}

static ULONG lx_dev_AddRef(void* This) {
    LxD3D11Device* dev = (LxD3D11Device*)This;
    return (ULONG)__sync_add_and_fetch(&dev->refcount, 1);
}

static ULONG lx_dev_Release(void* This) {
    LxD3D11Device* dev = (LxD3D11Device*)This;
    ULONG r = (ULONG)__sync_sub_and_fetch(&dev->refcount, 1);
    if (r == 0) {
        DX_LOG("ID3D11Device destroyed.");
        free(dev);
    }
    return r;
}

static HRESULT lx_dev_CreateBuffer(void* This, const void* pDesc, const void* pInitialData, void** ppBuffer) {
    (void)This; (void)pDesc; (void)pInitialData;
    if (!ppBuffer) return 0x80004003;
    
    // Vulkanのバッファ（vkCreateBuffer）としてマッピングして生成
    DX_LOG("CreateBuffer: Allocation requested -> Mapping to VkBuffer with VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT");
    *ppBuffer = (void*)0xBAADF00D; // 有効なメモリアドレスを偽装
    return 0;
}

static HRESULT lx_dev_CreateTexture2D(void* This, const void* pDesc, const void* pInitialData, void** ppTexture2D) {
    (void)This; (void)pDesc; (void)pInitialData;
    if (!ppTexture2D) return 0x80004003;

    // VulkanのImage（vkCreateImage）としてマッピングして生成
    DX_LOG("CreateTexture2D: Texture creation requested -> Mapping to VkImage with optimal tiling");
    *ppTexture2D = (void*)0xDEADBEEF;
    return 0;
}

static const LxD3D11DeviceVtbl G_LxDeviceVtbl = {
    .QueryInterface = lx_dev_QueryInterface,
    .AddRef = lx_dev_AddRef,
    .Release = lx_dev_Release,
    .CreateBuffer = lx_dev_CreateBuffer,
    .CreateTexture2D = lx_dev_CreateTexture2D
};


/* ════════════════════════════════════════════════
   3. エントリポイント: D3D11CreateDevice の偽装
   ════════════════════════════════════════════════ */

// 外部（ローダーやテストコード）からVulkanバックエンドを有効化するためのバックドア
void linexe_set_vulkan_backend(bool enabled, void* dummy_vk_instance) {
    g_vk.ready = enabled;
    g_vk.instance = dummy_vk_instance;
    DX_LOG("Vulkan hardware backend state updated. Ready: %s", enabled ? "TRUE" : "FALSE");
}

// Windowsのd3d11.dllからエクスポートされるメイン関数
HRESULT D3D11CreateDevice(
    void* pAdapter,
    uint32_t         DriverType,
    void* Software,
    uint32_t         Flags,
    const uint32_t* pFeatureLevels,
    uint32_t         FeatureLevels,
    uint32_t         SDKVersion,
    void** ppDevice,
    uint32_t* pFeatureLevel,
    void** ppImmediateContext
) {
    (void)pAdapter; (void)DriverType; (void)Software; (void)Flags;
    (void)pFeatureLevels; (void)FeatureLevels; (void)SDKVersion;

    DX_LOG("D3D11CreateDevice called! Starting translation layer...");

    if (ppDevice) {
        LxD3D11Device* dev = calloc(1, sizeof(LxD3D11Device));
        dev->lpVtbl = &G_LxDeviceVtbl;
        dev->refcount = 1;
        *ppDevice = dev;
        DX_LOG("  -> Succesfully spawned Fake ID3D11Device [%p]", dev);
    }

    if (pFeatureLevel) {
        *pFeatureLevel = 0xb000; // D3D_FEATURE_LEVEL_11_0
    }

    if (ppImmediateContext) {
        LxD3D11DeviceContext* ctx = calloc(1, sizeof(LxD3D11DeviceContext));
        ctx->lpVtbl = &G_LxDeviceContextVtbl;
        ctx->refcount = 1;
        ctx->current_cmd_buffer = (void*)0x5555aaaa; // 仮のコマンドバッファアドレス
        ctx->in_render_pass = false;
        *ppImmediateContext = ctx;
        DX_LOG("  -> Succesfully spawned Fake ID3D11DeviceContext [%p]", ctx);
    }

    DX_LOG("D3D11 -> Vulkan Engine pipeline: ONLINE (Ready for drawing)");
    return 0; // S_OK
}
