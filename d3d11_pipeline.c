/*
 * Linexe - D3D11 Pipeline & SwapChain (Phase 4.2 + 4.3)
 * Licensed under Apache License 2.0
 *
 * Phase 4.2: Graphics Pipeline 自動構築
 *   - D3D11 の PSO相当（blend/depth/rasterizer 状態）をVkPipelineに変換
 *   - RenderPass の自動生成（アタッチメント記述から）
 *
 * Phase 4.3: SwapChain → VkSwapchainKHR
 *   - DXGI_SWAP_CHAIN_DESC → VkSwapchainCreateInfoKHR
 *   - XCB サーフェス作成（Linux/X11環境）
 *   - Present ループの管理
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <dlfcn.h>

#include "dx_types.h"

#ifndef LINEXE_QUIET
  #define PL_LOG(fmt,...) fprintf(stderr,"[LINEXE/PIPE] " fmt "\n",##__VA_ARGS__)
#else
  #define PL_LOG(fmt,...)
#endif

/* ════════════════════════════════════════════════
   Phase 4.2: RenderPass 自動構築
   ════════════════════════════════════════════════ */

/* RenderPass キャッシュエントリ
 * アタッチメント構成をキーにしてVkRenderPassをキャッシュする */
typedef struct {
    uint32_t color_format;  /* VkFormat */
    uint32_t depth_format;  /* VkFormat, 0 = depth なし */
    uint32_t sample_count;  /* 1, 2, 4, 8... */
    uint64_t vk_render_pass;
} RenderPassCacheEntry;

#define MAX_RP_CACHE 64
static RenderPassCacheEntry rp_cache[MAX_RP_CACHE];
static int                  rp_cache_count = 0;

/* VkAttachmentDescription (簡略版) */
typedef struct {
    uint32_t flags;
    uint32_t format;
    uint32_t samples;
    uint32_t loadOp;
    uint32_t storeOp;
    uint32_t stencilLoadOp;
    uint32_t stencilStoreOp;
    uint32_t initialLayout;
    uint32_t finalLayout;
} VkAttachmentDesc;

/* VkAttachmentReference */
typedef struct { uint32_t attachment; uint32_t layout; } VkAttachRef;

/* VkSubpassDescription (簡略版) */
typedef struct {
    uint32_t flags;
    uint32_t pipelineBindPoint;
    uint32_t inputAttachmentCount; const VkAttachRef* pInputAttachments;
    uint32_t colorAttachmentCount; const VkAttachRef* pColorAttachments;
    const VkAttachRef* pResolveAttachments;
    const VkAttachRef* pDepthStencilAttachment;
    uint32_t preserveAttachmentCount; const uint32_t* pPreserveAttachments;
} VkSubpassDesc;

/* VkRenderPassCreateInfo */
typedef struct {
    uint32_t sType; const void* pNext; uint32_t flags;
    uint32_t attachmentCount; const VkAttachmentDesc* pAttachments;
    uint32_t subpassCount;    const VkSubpassDesc*    pSubpasses;
    uint32_t dependencyCount; const void*             pDependencies;
} VkRenderPassCI;

#define VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO 38
#define VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL   2
#define VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL 3
#define VK_IMAGE_LAYOUT_PRESENT_SRC_KHR 1000001002
#define VK_ATTACHMENT_LOAD_OP_CLEAR  1
#define VK_ATTACHMENT_STORE_OP_STORE 0
#define VK_ATTACHMENT_LOAD_OP_DONT_CARE  2
#define VK_ATTACHMENT_STORE_OP_DONT_CARE 1
#define VK_PIPELINE_BIND_POINT_GRAPHICS 0
#define VK_SAMPLE_COUNT_1_BIT 1

/* 外部から Vulkan デバイスを参照するための extern 宣言
 * d3d11_hook.c の g_vk.device を使う */
extern uint64_t g_vk_device_handle(void);
extern void*    g_vk_lib_handle(void);

/*
 * RenderPass 作成
 * color_fmt: VkFormat, depth_fmt: VkFormat (0=なし), samples: サンプル数
 */
uint64_t linexe_get_or_create_renderpass(uint64_t vk_device,
                                          void*    vk_lib,
                                          uint32_t color_fmt,
                                          uint32_t depth_fmt,
                                          uint32_t samples) {
    /* キャッシュ検索 */
    for (int i = 0; i < rp_cache_count; i++) {
        if (rp_cache[i].color_format == color_fmt &&
            rp_cache[i].depth_format == depth_fmt &&
            rp_cache[i].sample_count == samples) {
            PL_LOG("RenderPass cache HIT (color=%u depth=%u)", color_fmt, depth_fmt);
            return rp_cache[i].vk_render_pass;
        }
    }

    if (!vk_device || !vk_lib) {
        PL_LOG("RenderPass: no Vulkan device");
        return 0;
    }

    typedef int32_t (*PFN_vkCreateRenderPass_t)(
        uint64_t, const VkRenderPassCI*, const void*, uint64_t*);
    PFN_vkCreateRenderPass_t fn =
        (PFN_vkCreateRenderPass_t)dlsym(vk_lib, "vkCreateRenderPass");
    if (!fn) { PL_LOG("vkCreateRenderPass not found"); return 0; }

    /* アタッチメント記述 */
    VkAttachmentDesc attachments[2];
    int att_count = 0;

    /* カラーアタッチメント */
    memset(&attachments[0], 0, sizeof(attachments[0]));
    attachments[0].format        = color_fmt;
    attachments[0].samples       = samples ? samples : VK_SAMPLE_COUNT_1_BIT;
    attachments[0].loadOp        = VK_ATTACHMENT_LOAD_OP_CLEAR;
    attachments[0].storeOp       = VK_ATTACHMENT_STORE_OP_STORE;
    attachments[0].stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    attachments[0].stencilStoreOp= VK_ATTACHMENT_STORE_OP_DONT_CARE;
    attachments[0].initialLayout = 0; /* VK_IMAGE_LAYOUT_UNDEFINED */
    attachments[0].finalLayout   = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    att_count = 1;

    VkAttachRef color_ref = {0, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
    VkAttachRef depth_ref = {1, VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL};

    /* 深度アタッチメント（オプション） */
    if (depth_fmt != 0) {
        memset(&attachments[1], 0, sizeof(attachments[1]));
        attachments[1].format        = depth_fmt;
        attachments[1].samples       = samples ? samples : VK_SAMPLE_COUNT_1_BIT;
        attachments[1].loadOp        = VK_ATTACHMENT_LOAD_OP_CLEAR;
        attachments[1].storeOp       = VK_ATTACHMENT_STORE_OP_DONT_CARE;
        attachments[1].stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
        attachments[1].stencilStoreOp= VK_ATTACHMENT_STORE_OP_DONT_CARE;
        attachments[1].initialLayout = 0;
        attachments[1].finalLayout   = VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;
        att_count = 2;
    }

    VkSubpassDesc subpass = {0};
    subpass.pipelineBindPoint    = VK_PIPELINE_BIND_POINT_GRAPHICS;
    subpass.colorAttachmentCount = 1;
    subpass.pColorAttachments    = &color_ref;
    if (depth_fmt != 0) subpass.pDepthStencilAttachment = &depth_ref;

    VkRenderPassCI rp_ci = {
        VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO, NULL, 0,
        (uint32_t)att_count, attachments,
        1, &subpass,
        0, NULL
    };

    uint64_t rp = 0;
    int32_t r = fn(vk_device, &rp_ci, NULL, &rp);
    if (r != 0) { PL_LOG("vkCreateRenderPass failed: %d", r); return 0; }

    PL_LOG("RenderPass created: handle=%llu (color=%u, depth=%u)",
           (unsigned long long)rp, color_fmt, depth_fmt);

    /* キャッシュに登録 */
    if (rp_cache_count < MAX_RP_CACHE) {
        rp_cache[rp_cache_count].color_format  = color_fmt;
        rp_cache[rp_cache_count].depth_format  = depth_fmt;
        rp_cache[rp_cache_count].sample_count  = samples;
        rp_cache[rp_cache_count].vk_render_pass= rp;
        rp_cache_count++;
    }
    return rp;
}

/* ════════════════════════════════════════════════
   Phase 4.2: D3D11 ブレンドステート → Vulkan 変換
   ════════════════════════════════════════════════ */

/* VkBlendFactor */
typedef enum {
    VK_BLEND_FACTOR_ZERO                = 0,
    VK_BLEND_FACTOR_ONE                 = 1,
    VK_BLEND_FACTOR_SRC_ALPHA           = 6,
    VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA = 7,
    VK_BLEND_FACTOR_DST_ALPHA           = 8,
    VK_BLEND_FACTOR_ONE_MINUS_DST_ALPHA = 9,
} VkBlendFactor;

/* VkBlendOp */
typedef enum {
    VK_BLEND_OP_ADD              = 0,
    VK_BLEND_OP_SUBTRACT         = 1,
    VK_BLEND_OP_REVERSE_SUBTRACT = 2,
    VK_BLEND_OP_MIN              = 3,
    VK_BLEND_OP_MAX              = 4,
} VkBlendOp;

static uint32_t dx_blend_to_vk(UINT dx) {
    switch (dx) {
        case D3D11_BLEND_ZERO:            return VK_BLEND_FACTOR_ZERO;
        case D3D11_BLEND_ONE:             return VK_BLEND_FACTOR_ONE;
        case D3D11_BLEND_SRC_ALPHA:       return VK_BLEND_FACTOR_SRC_ALPHA;
        case D3D11_BLEND_INV_SRC_ALPHA:   return VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
        case D3D11_BLEND_DEST_ALPHA:      return VK_BLEND_FACTOR_DST_ALPHA;
        case D3D11_BLEND_INV_DEST_ALPHA:  return VK_BLEND_FACTOR_ONE_MINUS_DST_ALPHA;
        default:                          return VK_BLEND_FACTOR_ONE;
    }
}

static uint32_t dx_blend_op_to_vk(UINT dx) {
    switch (dx) {
        case D3D11_BLEND_OP_ADD:          return VK_BLEND_OP_ADD;
        case D3D11_BLEND_OP_SUBTRACT:     return VK_BLEND_OP_SUBTRACT;
        case D3D11_BLEND_OP_REV_SUBTRACT: return VK_BLEND_OP_REVERSE_SUBTRACT;
        case D3D11_BLEND_OP_MIN:          return VK_BLEND_OP_MIN;
        case D3D11_BLEND_OP_MAX:          return VK_BLEND_OP_MAX;
        default:                          return VK_BLEND_OP_ADD;
    }
}

/* VkPipelineColorBlendAttachmentState (48 bytes) */
typedef struct {
    uint32_t blendEnable;
    uint32_t srcColorBlendFactor;
    uint32_t dstColorBlendFactor;
    uint32_t colorBlendOp;
    uint32_t srcAlphaBlendFactor;
    uint32_t dstAlphaBlendFactor;
    uint32_t alphaBlendOp;
    uint32_t colorWriteMask;
} VkPipelineColorBlendAttachment;

void linexe_dx11_blend_to_vk(const D3D11_BLEND_DESC* dx,
                               VkPipelineColorBlendAttachment* vk_out,
                               int rt_index) {
    if (!dx || !vk_out || rt_index < 0 || rt_index > 7) return;
    const typeof(dx->RenderTarget[0])* rt = &dx->RenderTarget[rt_index];

    vk_out->blendEnable          = rt->BlendEnable ? 1 : 0;
    vk_out->srcColorBlendFactor  = dx_blend_to_vk(rt->SrcBlend);
    vk_out->dstColorBlendFactor  = dx_blend_to_vk(rt->DestBlend);
    vk_out->colorBlendOp         = dx_blend_op_to_vk(rt->BlendOp);
    vk_out->srcAlphaBlendFactor  = dx_blend_to_vk(rt->SrcBlendAlpha);
    vk_out->dstAlphaBlendFactor  = dx_blend_to_vk(rt->DestBlendAlpha);
    vk_out->alphaBlendOp         = dx_blend_op_to_vk(rt->BlendOpAlpha);
    vk_out->colorWriteMask       = rt->RenderTargetWriteMask & 0xF;

    PL_LOG("BlendState[%d]: enable=%u src=%u dst=%u op=%u",
           rt_index, vk_out->blendEnable,
           vk_out->srcColorBlendFactor,
           vk_out->dstColorBlendFactor,
           vk_out->colorBlendOp);
}

/* ════════════════════════════════════════════════
   Phase 4.2: D3D11 深度ステート → Vulkan
   ════════════════════════════════════════════════ */

/* VkCompareOp */
typedef enum {
    VK_COMPARE_OP_NEVER          = 0,
    VK_COMPARE_OP_LESS           = 1,
    VK_COMPARE_OP_EQUAL          = 2,
    VK_COMPARE_OP_LESS_OR_EQUAL  = 3,
    VK_COMPARE_OP_GREATER        = 4,
    VK_COMPARE_OP_NOT_EQUAL      = 5,
    VK_COMPARE_OP_GREATER_OR_EQUAL = 6,
    VK_COMPARE_OP_ALWAYS         = 7,
} VkCompareOp;

/* D3D11_COMPARISON_FUNC → VkCompareOp */
static uint32_t dx_cmp_to_vk(UINT dx) {
    if (dx == 0) return VK_COMPARE_OP_ALWAYS;
    /* D3D11_COMPARISON_FUNC: 1=NEVER, 2=LESS, 3=EQUAL, 4=LESS_EQUAL,
       5=GREATER, 6=NOT_EQUAL, 7=GREATER_EQUAL, 8=ALWAYS */
    static const uint32_t map[] = {
        VK_COMPARE_OP_NEVER, VK_COMPARE_OP_LESS, VK_COMPARE_OP_EQUAL,
        VK_COMPARE_OP_LESS_OR_EQUAL, VK_COMPARE_OP_GREATER,
        VK_COMPARE_OP_NOT_EQUAL, VK_COMPARE_OP_GREATER_OR_EQUAL,
        VK_COMPARE_OP_ALWAYS
    };
    if (dx >= 1 && dx <= 8) return map[dx - 1];
    return VK_COMPARE_OP_ALWAYS;
}

typedef struct {
    uint32_t depthTestEnable;
    uint32_t depthWriteEnable;
    uint32_t depthCompareOp;
    uint32_t depthBoundsTestEnable;
    uint32_t stencilTestEnable;
    /* stencil ops は省略（VkStencilOpState x2） */
} VkPipelineDepthStencilState;

void linexe_dx11_depth_to_vk(const D3D11_DEPTH_STENCIL_DESC* dx,
                               VkPipelineDepthStencilState* vk_out) {
    if (!dx || !vk_out) return;
    memset(vk_out, 0, sizeof(*vk_out));
    vk_out->depthTestEnable   = dx->DepthEnable ? 1 : 0;
    vk_out->depthWriteEnable  = (dx->DepthWriteMask != 0) ? 1 : 0;
    vk_out->depthCompareOp    = dx_cmp_to_vk(dx->DepthFunc);
    vk_out->stencilTestEnable = dx->StencilEnable ? 1 : 0;
    PL_LOG("DepthState: test=%u write=%u cmp=%u stencil=%u",
           vk_out->depthTestEnable, vk_out->depthWriteEnable,
           vk_out->depthCompareOp, vk_out->stencilTestEnable);
}

/* ════════════════════════════════════════════════
   Phase 4.2: D3D11 ラスタライザー → Vulkan
   ════════════════════════════════════════════════ */

/* VkCullModeFlags */
#define VK_CULL_MODE_NONE           0
#define VK_CULL_MODE_FRONT_BIT      1
#define VK_CULL_MODE_BACK_BIT       2
#define VK_CULL_MODE_FRONT_AND_BACK 3

typedef struct {
    uint32_t depthClampEnable;
    uint32_t rasterizerDiscardEnable;
    uint32_t polygonMode;    /* 0=FILL, 1=LINE, 2=POINT */
    uint32_t cullMode;
    uint32_t frontFace;      /* 0=CCW, 1=CW */
    uint32_t depthBiasEnable;
    float    depthBiasConstantFactor;
    float    depthBiasClamp;
    float    depthBiasSlopeFactor;
    float    lineWidth;
} VkPipelineRasterizerState;

void linexe_dx11_raster_to_vk(const D3D11_RASTERIZER_DESC* dx,
                                VkPipelineRasterizerState* vk_out) {
    if (!dx || !vk_out) return;
    memset(vk_out, 0, sizeof(*vk_out));
    vk_out->lineWidth = 1.0f;

    /* FillMode: 2=WIREFRAME, 3=SOLID */
    vk_out->polygonMode = (dx->FillMode == 2) ? 1 : 0;

    /* CullMode: 1=NONE, 2=FRONT, 3=BACK */
    switch (dx->CullMode) {
        case 1: vk_out->cullMode = VK_CULL_MODE_NONE;      break;
        case 2: vk_out->cullMode = VK_CULL_MODE_FRONT_BIT; break;
        case 3: vk_out->cullMode = VK_CULL_MODE_BACK_BIT;  break;
        default:vk_out->cullMode = VK_CULL_MODE_BACK_BIT;  break;
    }

    /* FrontCounterClockwise: DX=clockwise, Vulkan=CCW デフォルト */
    vk_out->frontFace = dx->FrontCounterClockwise ? 0 : 1;

    vk_out->depthBiasEnable         = (dx->DepthBias != 0) ? 1 : 0;
    vk_out->depthBiasConstantFactor = (float)dx->DepthBias;
    vk_out->depthBiasClamp          = dx->DepthBiasClamp;
    vk_out->depthBiasSlopeFactor    = dx->SlopeScaledDepthBias;
    vk_out->depthClampEnable        = dx->DepthClipEnable ? 0 : 1;

    PL_LOG("RasterizerState: fill=%u cull=%u front=%u depthBias=%u",
           vk_out->polygonMode, vk_out->cullMode,
           vk_out->frontFace, vk_out->depthBiasEnable);
}

/* ════════════════════════════════════════════════
   Phase 4.3: SwapChain 管理
   ════════════════════════════════════════════════ */

/* Linexe SwapChain 状態 */
typedef struct {
    int         initialized;
    uint32_t    width;
    uint32_t    height;
    DXGI_FORMAT format;
    int         vk_format; /* VkFormat */
    uint32_t    buffer_count;
    int         windowed;
    void*       xcb_connection;  /* xcb_connection_t* */
    uint32_t    xcb_window;
    uint64_t    vk_surface;      /* VkSurfaceKHR */
    uint64_t    vk_swapchain;    /* VkSwapchainKHR */
    uint64_t*   vk_images;       /* バックバッファ VkImage 配列 */
    uint32_t    image_count;
    uint32_t    current_image;
} LxSwapChain;

static LxSwapChain g_swapchain = {0};

/*
 * SwapChain 初期化
 * XCB サーフェスを作成してから VkSwapchainKHR を作成する。
 * GPU のない環境では VkSurfaceKHR 作成が失敗するため、
 * headless モードとして機能するフォールバックを持つ。
 */
int linexe_swapchain_init(const DXGI_SWAP_CHAIN_DESC* desc,
                           uint64_t vk_instance,
                           uint64_t vk_device,
                           void*    vk_lib) {
    if (!desc) return -1;

    g_swapchain.width        = desc->BufferDesc.Width  ? desc->BufferDesc.Width  : 800;
    g_swapchain.height       = desc->BufferDesc.Height ? desc->BufferDesc.Height : 600;
    g_swapchain.format       = desc->BufferDesc.Format;
    g_swapchain.vk_format    = dxgi_to_vk_format(desc->BufferDesc.Format);
    g_swapchain.buffer_count = desc->BufferCount ? desc->BufferCount : 2;
    g_swapchain.windowed     = desc->Windowed;

    PL_LOG("SwapChain init: %ux%u fmt=%s bufs=%u windowed=%u",
           g_swapchain.width, g_swapchain.height,
           dxgi_format_name(desc->BufferDesc.Format),
           g_swapchain.buffer_count, g_swapchain.windowed);

    /* XCB 接続試行 */
    void* xcb_lib = dlopen("libxcb.so.1", RTLD_LAZY);
    if (xcb_lib) {
        typedef void* (*PFN_xcb_connect)(const char*, int*);
        typedef uint32_t (*PFN_xcb_generate_id)(void*);
        typedef void* (*PFN_xcb_create_window_checked)(void*,...);

        PFN_xcb_connect xcb_connect =
            (PFN_xcb_connect)dlsym(xcb_lib, "xcb_connect");
        PFN_xcb_generate_id xcb_gen_id =
            (PFN_xcb_generate_id)dlsym(xcb_lib, "xcb_generate_id");

        if (xcb_connect && xcb_gen_id) {
            int screen_num = 0;
            void* conn = xcb_connect(NULL, &screen_num);
            if (conn) {
                g_swapchain.xcb_connection = conn;
                g_swapchain.xcb_window     = xcb_gen_id(conn);
                PL_LOG("XCB connection established (screen=%d, win=0x%X)",
                       screen_num, g_swapchain.xcb_window);

                /* VkXcbSurfaceCreateInfoKHR */
                typedef struct {
                    uint32_t sType; const void* pNext; uint32_t flags;
                    void* connection; uint32_t window;
                } VkXcbSurfaceCI;
                typedef int32_t (*PFN_vkCreateXcbSurface)(
                    uint64_t, const VkXcbSurfaceCI*, const void*, uint64_t*);
                PFN_vkCreateXcbSurface createSurface =
                    (PFN_vkCreateXcbSurface)dlsym(vk_lib, "vkCreateXcbSurfaceKHR");

                if (createSurface) {
                    VkXcbSurfaceCI sci = {
                        1000005000, NULL, 0,  /* VK_STRUCTURE_TYPE_XCB_SURFACE_CREATE_INFO_KHR */
                        conn, g_swapchain.xcb_window
                    };
                    int32_t r = createSurface(vk_instance, &sci, NULL, &g_swapchain.vk_surface);
                    if (r == 0) {
                        PL_LOG("VkSurfaceKHR created: %llu",
                               (unsigned long long)g_swapchain.vk_surface);
                    } else {
                        PL_LOG("vkCreateXcbSurfaceKHR failed: %d (headless mode)", r);
                    }
                }
            }
        }
        dlclose(xcb_lib);
    }

    /* VkSwapchain 作成（サーフェスがある場合のみ） */
    if (g_swapchain.vk_surface && vk_device && vk_lib) {
        typedef struct {
            uint32_t sType; const void* pNext; uint32_t flags;
            uint64_t surface;
            uint32_t minImageCount;
            uint32_t imageFormat;
            uint32_t imageColorSpace;
            struct { uint32_t w; uint32_t h; } imageExtent;
            uint32_t imageArrayLayers;
            uint32_t imageUsage;
            uint32_t imageSharingMode;
            uint32_t queueFamilyIndexCount; const uint32_t* pQueueFamilyIndices;
            uint32_t preTransform;
            uint32_t compositeAlpha;
            uint32_t presentMode;
            uint32_t clipped;
            uint64_t oldSwapchain;
        } VkSwapchainCI;

        typedef int32_t (*PFN_vkCreateSwapchain)(
            uint64_t, const VkSwapchainCI*, const void*, uint64_t*);
        PFN_vkCreateSwapchain createSC =
            (PFN_vkCreateSwapchain)dlsym(vk_lib, "vkCreateSwapchainKHR");

        if (createSC) {
            VkSwapchainCI sci = {
                1000001000, NULL, 0,  /* VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR */
                g_swapchain.vk_surface,
                g_swapchain.buffer_count,
                (uint32_t)g_swapchain.vk_format,
                0, /* VK_COLOR_SPACE_SRGB_NONLINEAR_KHR */
                {g_swapchain.width, g_swapchain.height},
                1, /* imageArrayLayers */
                0x00000010, /* VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT */
                0, /* EXCLUSIVE */
                0, NULL,
                0x00000001, /* VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR */
                0x00000001, /* VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR */
                0, /* VK_PRESENT_MODE_IMMEDIATE_KHR */
                1, /* clipped */
                0  /* oldSwapchain */
            };
            int32_t r = createSC(vk_device, &sci, NULL, &g_swapchain.vk_swapchain);
            if (r == 0)
                PL_LOG("VkSwapchainKHR created: %llu",
                       (unsigned long long)g_swapchain.vk_swapchain);
            else
                PL_LOG("vkCreateSwapchainKHR failed: %d", r);
        }
    }

    g_swapchain.initialized = 1;
    PL_LOG("SwapChain ready (surface=%llu swapchain=%llu)",
           (unsigned long long)g_swapchain.vk_surface,
           (unsigned long long)g_swapchain.vk_swapchain);
    return 0;
}

/* Present: 次のフレームを表示 */
int linexe_swapchain_present(uint64_t vk_queue, void* vk_lib) {
    if (!g_swapchain.initialized) return -1;

    g_swapchain.current_image =
        (g_swapchain.current_image + 1) % g_swapchain.buffer_count;

    if (!g_swapchain.vk_swapchain || !vk_queue || !vk_lib) {
        /* headless: フレームカウントだけ進める */
        return 0;
    }

    typedef struct {
        uint32_t sType; const void* pNext;
        uint32_t waitSemaphoreCount; const uint64_t* pWaitSemaphores;
        uint32_t swapchainCount;     const uint64_t* pSwapchains;
        const uint32_t* pImageIndices;
        int32_t* pResults;
    } VkPresentInfoKHR;

    typedef int32_t (*PFN_vkQueuePresent)(uint64_t, const VkPresentInfoKHR*);
    PFN_vkQueuePresent present =
        (PFN_vkQueuePresent)dlsym(vk_lib, "vkQueuePresentKHR");
    if (!present) return -1;

    VkPresentInfoKHR pi = {
        1000001001, NULL, 0, NULL,
        1, &g_swapchain.vk_swapchain,
        &g_swapchain.current_image,
        NULL
    };
    int32_t r = present(vk_queue, &pi);
    if (r != 0) PL_LOG("vkQueuePresentKHR: %d", r);
    return r == 0 ? 0 : -1;
}

/* SwapChain 情報取得 */
void linexe_swapchain_info(uint32_t* w, uint32_t* h, int* fmt, int* ready) {
    if (w)   *w   = g_swapchain.width;
    if (h)   *h   = g_swapchain.height;
    if (fmt) *fmt = g_swapchain.vk_format;
    if (ready) *ready = g_swapchain.initialized &&
                       (g_swapchain.vk_swapchain != 0 || 1 /* headless OK */);
}
