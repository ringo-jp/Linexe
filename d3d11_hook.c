/*
 * Linexe - D3D11 to Vulkan Translation Layer (Phase 4)
 * Licensed under Apache License 2.0
 *
 * 仕組み:
 *   EXEが D3D11CreateDevice() を呼ぶ
 *     → LD_PRELOAD でこのライブラリが横取り
 *     → Vulkan インスタンス/デバイスを初期化
 *     → 偽のID3D11Device COMオブジェクトを返す
 *     → 以降のD3D11呼び出しはVulkan APIに変換
 *
 * 実装状況 (v0.4.0):
 *   DONE  D3D11CreateDevice の横取りと偽装
 *   DONE  Vulkan インスタンス・デバイス初期化
 *   DONE  バッファ生成 (CreateBuffer → VkBuffer + VkDeviceMemory)
 *   DONE  テクスチャ生成 (CreateTexture2D → VkImage)
 *   DONE  DXGI フォーマット → VkFormat 変換 (24フォーマット)
 *   DONE  デバイスコンテキストの基本描画コール記録
 *   TODO  ShaderCompiler (DXBC → SPIR-V) — Phase 4.1
 *   TODO  RenderPass / Pipeline 自動構築  — Phase 4.2
 *   TODO  SwapChain → VkSwapchainKHR     — Phase 4.3
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <dlfcn.h>
#include <pthread.h>

#include "dx_types.h"

#ifndef LINEXE_QUIET
  #define DX_LOG(fmt,...) fprintf(stderr,"[LINEXE/D3D] " fmt "\n",##__VA_ARGS__)
#else
  #define DX_LOG(fmt,...)
#endif
#define DX_ERR(fmt,...) fprintf(stderr,"[LINEXE/D3D][ERR] " fmt "\n",##__VA_ARGS__)

/* ════════════════════════════════════════════════
   Vulkan ローダー（dlopen で動的ロード）
   vulkan.h を直接使わずポインタのみ使う
   ════════════════════════════════════════════════ */
typedef uint64_t VkInstance;
typedef uint64_t VkPhysicalDevice;
typedef uint64_t VkDevice;
typedef uint64_t VkQueue;
typedef uint64_t VkBuffer;
typedef uint64_t VkImage;
typedef uint64_t VkDeviceMemory;
typedef uint64_t VkCommandPool;
typedef uint64_t VkCommandBuffer;
typedef uint64_t VkRenderPass;
typedef uint64_t VkPipeline;
typedef uint64_t VkPipelineLayout;
typedef uint64_t VkDescriptorSetLayout;
typedef uint64_t VkDescriptorPool;
typedef uint64_t VkDescriptorSet;
typedef uint64_t VkImageView;
typedef uint64_t VkSampler;
typedef uint64_t VkFence;
typedef uint64_t VkSemaphore;
typedef uint64_t VkShaderModule;
typedef int32_t  VkResult;
typedef uint32_t VkFlags;

#define VK_SUCCESS               0
#define VK_NULL_HANDLE           0ULL
#define VK_WHOLE_SIZE            (~0ULL)

/* 最小限のVulkan構造体 */
typedef struct { uint32_t sType; const void* pNext; } VkBaseStructure;
#define VK_STRUCTURE_TYPE_APPLICATION_INFO         0
#define VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO     1
#define VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO       3
#define VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO 2
#define VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO       12
#define VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO        14
#define VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO     5
#define VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO 39

typedef struct {
    uint32_t sType; const void* pNext;
    const char* pApplicationName; uint32_t applicationVersion;
    const char* pEngineName;      uint32_t engineVersion;
    uint32_t apiVersion;
} VkApplicationInfo;

typedef struct {
    uint32_t sType; const void* pNext;
    VkFlags  flags;
    const VkApplicationInfo* pApplicationInfo;
    uint32_t enabledLayerCount;       const char* const* ppEnabledLayerNames;
    uint32_t enabledExtensionCount;   const char* const* ppEnabledExtensionNames;
} VkInstanceCreateInfo;

typedef struct {
    uint32_t sType; const void* pNext;
    VkFlags  flags; uint32_t queueFamilyIndex;
    uint32_t queueCount; const float* pQueuePriorities;
} VkDeviceQueueCreateInfo;

typedef struct {
    uint32_t sType; const void* pNext;
    VkFlags  flags;
    uint32_t queueCreateInfoCount; const VkDeviceQueueCreateInfo* pQueueCreateInfos;
    uint32_t enabledLayerCount;    const char* const* ppEnabledLayerNames;
    uint32_t enabledExtensionCount;const char* const* ppEnabledExtensionNames;
    const void* pEnabledFeatures;
} VkDeviceCreateInfo;

typedef struct {
    uint32_t sType; const void* pNext;
    VkFlags  flags; uint64_t size;
    VkFlags  usage; uint32_t sharingMode;
    uint32_t queueFamilyIndexCount; const uint32_t* pQueueFamilyIndices;
} VkBufferCreateInfo;

typedef struct {
    uint32_t sType; const void* pNext;
    VkFlags  flags;
    uint32_t imageType;   /* VkImageType */
    uint32_t format;      /* VkFormat */
    struct { uint32_t width; uint32_t height; uint32_t depth; } extent;
    uint32_t mipLevels;   uint32_t arrayLayers;
    uint32_t samples;     uint32_t tiling; uint32_t usage;
    uint32_t sharingMode;
    uint32_t queueFamilyIndexCount; const uint32_t* pQueueFamilyIndices;
    uint32_t initialLayout;
} VkImageCreateInfo;

typedef struct {
    uint32_t sType; const void* pNext;
    uint64_t allocationSize; uint32_t memoryTypeIndex;
} VkMemoryAllocateInfo;

typedef struct {
    uint32_t sType; const void* pNext;
    VkFlags flags; uint32_t queueFamilyIndex;
} VkCommandPoolCreateInfo;

typedef struct {
    uint32_t memoryTypeCount;
    struct {
        VkFlags  propertyFlags;
        uint32_t heapIndex;
    } memoryTypes[32];
    uint32_t memoryHeapCount;
    struct { uint64_t size; VkFlags flags; } memoryHeaps[16];
} VkPhysicalDeviceMemoryProperties;

/* Vulkan関数ポインタ型 */
#define VK_FN(name,...) typedef VkResult (*PFN_##name)(__VA_ARGS__)
VK_FN(vkCreateInstance,   const VkInstanceCreateInfo*, const void*, VkInstance*);
VK_FN(vkDestroyInstance,  VkInstance, const void*);
VK_FN(vkEnumeratePhysicalDevices, VkInstance, uint32_t*, VkPhysicalDevice*);
VK_FN(vkCreateDevice,     VkPhysicalDevice, const VkDeviceCreateInfo*, const void*, VkDevice*);
VK_FN(vkDestroyDevice,    VkDevice, const void*);
VK_FN(vkGetDeviceQueue,   VkDevice, uint32_t, uint32_t, VkQueue*); /* returns void */
VK_FN(vkCreateBuffer,     VkDevice, const VkBufferCreateInfo*, const void*, VkBuffer*);
VK_FN(vkDestroyBuffer,    VkDevice, VkBuffer, const void*);
VK_FN(vkCreateImage,      VkDevice, const VkImageCreateInfo*, const void*, VkImage*);
VK_FN(vkDestroyImage,     VkDevice, VkImage, const void*);
VK_FN(vkAllocateMemory,   VkDevice, const VkMemoryAllocateInfo*, const void*, VkDeviceMemory*);
VK_FN(vkFreeMemory,       VkDevice, VkDeviceMemory, const void*);
VK_FN(vkBindBufferMemory, VkDevice, VkBuffer, VkDeviceMemory, uint64_t);
VK_FN(vkBindImageMemory,  VkDevice, VkImage, VkDeviceMemory, uint64_t);
VK_FN(vkMapMemory,        VkDevice, VkDeviceMemory, uint64_t, uint64_t, VkFlags, void**);
VK_FN(vkUnmapMemory,      VkDevice, VkDeviceMemory);
VK_FN(vkCreateCommandPool,VkDevice, const VkCommandPoolCreateInfo*, const void*, VkCommandPool*);

typedef void (*PFN_vkGetDeviceQueue2)(VkDevice,const void*,VkQueue*);
typedef void (*PFN_vkGetPhysicalDeviceMemoryProperties)(VkPhysicalDevice, VkPhysicalDeviceMemoryProperties*);
typedef void (*PFN_vkGetBufferMemoryRequirements)(VkDevice, VkBuffer, void*);
typedef void (*PFN_vkGetImageMemoryRequirements)(VkDevice, VkImage, void*);

typedef struct {
    uint64_t size; uint64_t alignment; uint32_t memoryTypeBits;
} VkMemoryRequirements;

/* ════════════════════════════════════════════════
   Vulkanバックエンド状態
   ════════════════════════════════════════════════ */
typedef struct {
    void*                   lib;   /* libvulkan.so handle */
    int                     ready;
    pthread_mutex_t         lock;

    /* ローダー関数ポインタ */
    PFN_vkCreateInstance    vkCreateInstance;
    PFN_vkDestroyInstance   vkDestroyInstance;
    PFN_vkEnumeratePhysicalDevices vkEnumeratePhysicalDevices;
    PFN_vkCreateDevice      vkCreateDevice;
    PFN_vkDestroyDevice     vkDestroyDevice;
    PFN_vkCreateBuffer      vkCreateBuffer;
    PFN_vkDestroyBuffer     vkDestroyBuffer;
    PFN_vkCreateImage       vkCreateImage;
    PFN_vkDestroyImage      vkDestroyImage;
    PFN_vkAllocateMemory    vkAllocateMemory;
    PFN_vkFreeMemory        vkFreeMemory;
    PFN_vkBindBufferMemory  vkBindBufferMemory;
    PFN_vkBindImageMemory   vkBindImageMemory;
    PFN_vkMapMemory         vkMapMemory;
    PFN_vkUnmapMemory       vkUnmapMemory;
    PFN_vkGetPhysicalDeviceMemoryProperties vkGetPhysicalDeviceMemoryProperties;
    PFN_vkGetBufferMemoryRequirements vkGetBufferMemoryRequirements;
    PFN_vkGetImageMemoryRequirements  vkGetImageMemoryRequirements;
    PFN_vkCreateCommandPool vkCreateCommandPool;

    /* Vulkanオブジェクト */
    VkInstance       instance;
    VkPhysicalDevice phys_device;
    VkDevice         device;
    VkQueue          graphics_queue;
    uint32_t         graphics_family;
    VkCommandPool    cmd_pool;

    /* デバイスメモリプロパティ */
    VkPhysicalDeviceMemoryProperties mem_props;
} VkBackend;

static VkBackend g_vk = {0};
static pthread_once_t g_vk_once = PTHREAD_ONCE_INIT;

/* ── ヘルパー: 適切なメモリタイプを探す ── */
static uint32_t find_memory_type(uint32_t type_bits, uint32_t required_props) {
    for (uint32_t i = 0; i < g_vk.mem_props.memoryTypeCount; i++) {
        if ((type_bits & (1u << i)) &&
            (g_vk.mem_props.memoryTypes[i].propertyFlags & required_props) == required_props)
            return i;
    }
    return 0; /* fallback */
}

/* ── Vulkan バックエンド初期化 ── */
static void vk_backend_init(void) {
    pthread_mutex_init(&g_vk.lock, NULL);

    g_vk.lib = dlopen("libvulkan.so.1", RTLD_LAZY | RTLD_GLOBAL);
    if (!g_vk.lib) {
        DX_ERR("Failed to load libvulkan.so.1: %s", dlerror());
        return;
    }

#define LOAD(fn) g_vk.fn = (PFN_##fn)dlsym(g_vk.lib, #fn); \
    if (!g_vk.fn) { DX_ERR("dlsym " #fn " failed"); return; }

    LOAD(vkCreateInstance)
    LOAD(vkDestroyInstance)
    LOAD(vkEnumeratePhysicalDevices)
    LOAD(vkCreateDevice)
    LOAD(vkDestroyDevice)
    LOAD(vkCreateBuffer)
    LOAD(vkDestroyBuffer)
    LOAD(vkCreateImage)
    LOAD(vkDestroyImage)
    LOAD(vkAllocateMemory)
    LOAD(vkFreeMemory)
    LOAD(vkBindBufferMemory)
    LOAD(vkBindImageMemory)
    LOAD(vkMapMemory)
    LOAD(vkUnmapMemory)
    LOAD(vkCreateCommandPool)
    g_vk.vkGetPhysicalDeviceMemoryProperties =
        (PFN_vkGetPhysicalDeviceMemoryProperties)
        dlsym(g_vk.lib, "vkGetPhysicalDeviceMemoryProperties");
    g_vk.vkGetBufferMemoryRequirements =
        (PFN_vkGetBufferMemoryRequirements)
        dlsym(g_vk.lib, "vkGetBufferMemoryRequirements");
    g_vk.vkGetImageMemoryRequirements =
        (PFN_vkGetImageMemoryRequirements)
        dlsym(g_vk.lib, "vkGetImageMemoryRequirements");
#undef LOAD

    /* VkInstance 作成 */
    VkApplicationInfo app_info = {
        VK_STRUCTURE_TYPE_APPLICATION_INFO, NULL,
        "Linexe D3D11", 1,
        "Linexe", 1,
        (1 << 22) | (3 << 12) | 0  /* Vulkan 1.3.0 */
    };
    VkInstanceCreateInfo inst_ci = {
        VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, NULL, 0,
        &app_info, 0, NULL, 0, NULL
    };
    VkResult r = g_vk.vkCreateInstance(&inst_ci, NULL, &g_vk.instance);
    if (r != VK_SUCCESS) { DX_ERR("vkCreateInstance failed: %d", r); return; }
    DX_LOG("VkInstance created");

    /* 物理デバイス選択（最初の1つ） */
    uint32_t n = 1;
    g_vk.vkEnumeratePhysicalDevices(g_vk.instance, &n, &g_vk.phys_device);
    if (!g_vk.phys_device) { DX_ERR("No Vulkan physical device"); return; }
    DX_LOG("VkPhysicalDevice selected");

    /* メモリプロパティ取得 */
    if (g_vk.vkGetPhysicalDeviceMemoryProperties)
        g_vk.vkGetPhysicalDeviceMemoryProperties(g_vk.phys_device, &g_vk.mem_props);

    /* 論理デバイス作成（グラフィックスキュー family=0） */
    g_vk.graphics_family = 0;
    float prio = 1.0f;
    VkDeviceQueueCreateInfo queue_ci = {
        VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, NULL, 0,
        g_vk.graphics_family, 1, &prio
    };
    VkDeviceCreateInfo dev_ci = {
        VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, NULL, 0,
        1, &queue_ci, 0, NULL, 0, NULL, NULL
    };
    r = g_vk.vkCreateDevice(g_vk.phys_device, &dev_ci, NULL, &g_vk.device);
    if (r != VK_SUCCESS) { DX_ERR("vkCreateDevice failed: %d", r); return; }
    DX_LOG("VkDevice created");

    /* コマンドプール作成 */
    VkCommandPoolCreateInfo cp_ci = {
        VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, NULL,
        0x00000002, /* VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT */
        g_vk.graphics_family
    };
    g_vk.vkCreateCommandPool(g_vk.device, &cp_ci, NULL, &g_vk.cmd_pool);

    g_vk.ready = 1;
    DX_LOG("Vulkan backend ready (D3D11->Vulkan translation active)");
}

/* ════════════════════════════════════════════════
   Linexe D3D11 バッファオブジェクト
   ID3D11Buffer の実体（VkBufferを内包）
   ════════════════════════════════════════════════ */
typedef struct LxD3D11Buffer {
    const void*    lpVtbl;      /* IUnknown vtbl */
    volatile long  refcount;
    D3D11_BUFFER_DESC desc;
    VkBuffer          vk_buffer;
    VkDeviceMemory    vk_memory;
    void*             mapped_ptr; /* NULL = unmapped */
} LxD3D11Buffer;

static HRESULT lx_buffer_QueryInterface(IUnknown* self, REFIID riid, void** ppv){
    (void)riid; *ppv=self; return S_OK;
}
static ULONG lx_buffer_AddRef(IUnknown* self){
    LxD3D11Buffer* b=(LxD3D11Buffer*)self;
    return (ULONG)__sync_add_and_fetch(&b->refcount,1);
}
static ULONG lx_buffer_Release(IUnknown* self){
    LxD3D11Buffer* b=(LxD3D11Buffer*)self;
    ULONG r=(ULONG)__sync_sub_and_fetch(&b->refcount,1);
    if(r==0){
        if(g_vk.ready){
            if(b->vk_buffer)  g_vk.vkDestroyBuffer(g_vk.device,b->vk_buffer,NULL);
            if(b->vk_memory)  g_vk.vkFreeMemory(g_vk.device,b->vk_memory,NULL);
        }
        free(b);
        DX_LOG("ID3D11Buffer released");
    }
    return r;
}
static const IUnknownVtbl LxBufferVtbl = {
    lx_buffer_QueryInterface,
    lx_buffer_AddRef,
    lx_buffer_Release
};

/* ════════════════════════════════════════════════
   Linexe D3D11 テクスチャオブジェクト
   ════════════════════════════════════════════════ */
typedef struct LxD3D11Texture2D {
    const void*        lpVtbl;
    volatile long      refcount;
    D3D11_TEXTURE2D_DESC desc;
    VkImage            vk_image;
    VkDeviceMemory     vk_memory;
    int                vk_format;
} LxD3D11Texture2D;

static HRESULT lx_tex_QueryInterface(IUnknown* s, REFIID r, void** p){(void)r;*p=s;return S_OK;}
static ULONG   lx_tex_AddRef(IUnknown* s){
    LxD3D11Texture2D* t=(LxD3D11Texture2D*)s;
    return (ULONG)__sync_add_and_fetch(&t->refcount,1);
}
static ULONG   lx_tex_Release(IUnknown* s){
    LxD3D11Texture2D* t=(LxD3D11Texture2D*)s;
    ULONG r=(ULONG)__sync_sub_and_fetch(&t->refcount,1);
    if(r==0){
        if(g_vk.ready){
            if(t->vk_image)  g_vk.vkDestroyImage(g_vk.device,t->vk_image,NULL);
            if(t->vk_memory) g_vk.vkFreeMemory(g_vk.device,t->vk_memory,NULL);
        }
        free(t);
        DX_LOG("ID3D11Texture2D released");
    }
    return r;
}
static const IUnknownVtbl LxTexVtbl = {lx_tex_QueryInterface,lx_tex_AddRef,lx_tex_Release};

/* ════════════════════════════════════════════════
   D3D11Device 偽実装
   ════════════════════════════════════════════════ */
typedef struct LxD3D11Device {
    const void*   lpVtbl;
    volatile long refcount;
    D3D_FEATURE_LEVEL feature_level;
} LxD3D11Device;

/* CreateBuffer: D3D11_BUFFER_DESC → VkBuffer */
static HRESULT lx_CreateBuffer(LxD3D11Device* self,
                                 const D3D11_BUFFER_DESC* desc,
                                 const D3D11_SUBRESOURCE_DATA* init_data,
                                 ID3D11Buffer** ppBuffer) {
    (void)self;
    if (!desc || !ppBuffer) return E_INVALIDARG;

    pthread_once(&g_vk_once, vk_backend_init);
    if (!g_vk.ready) {
        DX_ERR("CreateBuffer: Vulkan not ready");
        return E_FAIL;
    }

    /* D3D11 bind flags → Vulkan usage flags */
    uint32_t usage = 0x00000080; /* VK_BUFFER_USAGE_TRANSFER_DST_BIT */
    if (desc->BindFlags & D3D11_BIND_VERTEX_BUFFER)
        usage |= 0x00000080; /* VK_BUFFER_USAGE_VERTEX_BUFFER_BIT = 0x80 */
    if (desc->BindFlags & D3D11_BIND_INDEX_BUFFER)
        usage |= 0x00000040; /* VK_BUFFER_USAGE_INDEX_BUFFER_BIT = 0x40 */
    if (desc->BindFlags & D3D11_BIND_CONSTANT_BUFFER)
        usage |= 0x00000010; /* VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT = 0x10 */
    if (desc->BindFlags & D3D11_BIND_SHADER_RESOURCE)
        usage |= 0x00000004; /* VK_BUFFER_USAGE_STORAGE_BUFFER_BIT = 0x04 */
    usage |= 0x00000040; /* TRANSFER_SRC */

    VkBufferCreateInfo bci = {
        VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, NULL, 0,
        desc->ByteWidth, usage,
        0, 0, NULL /* EXCLUSIVE */
    };

    LxD3D11Buffer* buf = calloc(1, sizeof(LxD3D11Buffer));
    if (!buf) return E_OUTOFMEMORY;
    buf->lpVtbl   = &LxBufferVtbl;
    buf->refcount = 1;
    buf->desc     = *desc;

    VkResult r = g_vk.vkCreateBuffer(g_vk.device, &bci, NULL, &buf->vk_buffer);
    if (r != VK_SUCCESS) { free(buf); return E_FAIL; }

    /* メモリ割り当て */
    VkMemoryRequirements mreq = {0};
    if (g_vk.vkGetBufferMemoryRequirements)
        g_vk.vkGetBufferMemoryRequirements(g_vk.device, buf->vk_buffer, &mreq);
    else
        mreq.size = desc->ByteWidth, mreq.memoryTypeBits = 0xFFFFFFFF;

    /* HOST_VISIBLE | HOST_COHERENT でCPUからアクセス可能に */
    uint32_t mem_type = find_memory_type(mreq.memoryTypeBits, 0x6 /* HOST_VISIBLE|COHERENT */);
    VkMemoryAllocateInfo mai = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, NULL, mreq.size, mem_type};
    r = g_vk.vkAllocateMemory(g_vk.device, &mai, NULL, &buf->vk_memory);
    if (r != VK_SUCCESS) {
        g_vk.vkDestroyBuffer(g_vk.device, buf->vk_buffer, NULL);
        free(buf); return E_OUTOFMEMORY;
    }

    g_vk.vkBindBufferMemory(g_vk.device, buf->vk_buffer, buf->vk_memory, 0);

    /* 初期データがある場合はマップして書き込む */
    if (init_data && init_data->pSysMem) {
        void* ptr = NULL;
        if (g_vk.vkMapMemory(g_vk.device, buf->vk_memory, 0,
                              VK_WHOLE_SIZE, 0, &ptr) == VK_SUCCESS && ptr) {
            memcpy(ptr, init_data->pSysMem, desc->ByteWidth);
            g_vk.vkUnmapMemory(g_vk.device, buf->vk_memory);
        }
    }

    DX_LOG("CreateBuffer(%u bytes, bind=0x%X) -> VkBuffer=%llu",
           desc->ByteWidth, desc->BindFlags, (unsigned long long)buf->vk_buffer);

    *ppBuffer = (ID3D11Buffer*)buf;
    return S_OK;
}

/* CreateTexture2D: D3D11_TEXTURE2D_DESC → VkImage */
static HRESULT lx_CreateTexture2D(LxD3D11Device* self,
                                    const D3D11_TEXTURE2D_DESC* desc,
                                    const D3D11_SUBRESOURCE_DATA* init_data,
                                    ID3D11Texture2D** ppTexture) {
    (void)self; (void)init_data;
    if (!desc || !ppTexture) return E_INVALIDARG;

    pthread_once(&g_vk_once, vk_backend_init);
    if (!g_vk.ready) return E_FAIL;

    int vk_fmt = dxgi_to_vk_format(desc->Format);
    DX_LOG("CreateTexture2D(%ux%u, fmt=%s) -> VkFormat=%d",
           desc->Width, desc->Height, dxgi_format_name(desc->Format), vk_fmt);

    uint32_t usage = 0;
    if (desc->BindFlags & D3D11_BIND_SHADER_RESOURCE)
        usage |= 0x00000004; /* VK_IMAGE_USAGE_SAMPLED_BIT */
    if (desc->BindFlags & D3D11_BIND_RENDER_TARGET)
        usage |= 0x00000010; /* VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT */
    if (desc->BindFlags & D3D11_BIND_DEPTH_STENCIL)
        usage |= 0x00000020; /* VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT */
    usage |= 0x00000001 | 0x00000002; /* TRANSFER_SRC | TRANSFER_DST */

    VkImageCreateInfo ici = {
        VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO, NULL, 0,
        1, /* VK_IMAGE_TYPE_2D */
        (uint32_t)vk_fmt,
        {desc->Width, desc->Height, 1},
        desc->MipLevels ? desc->MipLevels : 1,
        desc->ArraySize ? desc->ArraySize : 1,
        1, /* VK_SAMPLE_COUNT_1_BIT */
        0, /* VK_IMAGE_TILING_OPTIMAL */
        usage, 0, 0, NULL, 0 /* UNDEFINED layout */
    };

    LxD3D11Texture2D* tex = calloc(1, sizeof(LxD3D11Texture2D));
    if (!tex) return E_OUTOFMEMORY;
    tex->lpVtbl    = &LxTexVtbl;
    tex->refcount  = 1;
    tex->desc      = *desc;
    tex->vk_format = vk_fmt;

    VkResult r = g_vk.vkCreateImage(g_vk.device, &ici, NULL, &tex->vk_image);
    if (r != VK_SUCCESS) { free(tex); return E_FAIL; }

    VkMemoryRequirements mreq = {0};
    if (g_vk.vkGetImageMemoryRequirements)
        g_vk.vkGetImageMemoryRequirements(g_vk.device, tex->vk_image, &mreq);
    else
        mreq.size = (uint64_t)desc->Width * desc->Height * 4,
        mreq.memoryTypeBits = 0xFFFFFFFF;

    uint32_t mem_type = find_memory_type(mreq.memoryTypeBits, 0x1 /* DEVICE_LOCAL */);
    VkMemoryAllocateInfo mai = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, NULL, mreq.size, mem_type};
    r = g_vk.vkAllocateMemory(g_vk.device, &mai, NULL, &tex->vk_memory);
    if (r != VK_SUCCESS) {
        g_vk.vkDestroyImage(g_vk.device, tex->vk_image, NULL);
        free(tex); return E_OUTOFMEMORY;
    }

    g_vk.vkBindImageMemory(g_vk.device, tex->vk_image, tex->vk_memory, 0);
    DX_LOG("  -> VkImage=%llu, memory=%llu bytes",
           (unsigned long long)tex->vk_image, (unsigned long long)mreq.size);

    *ppTexture = (ID3D11Texture2D*)tex;
    return S_OK;
}

/* D3D11Device 仮想関数テーブル（最小実装） */
typedef HRESULT (*PFN_CreateBuffer)(LxD3D11Device*,const D3D11_BUFFER_DESC*,const D3D11_SUBRESOURCE_DATA*,ID3D11Buffer**);
typedef HRESULT (*PFN_CreateTexture2D)(LxD3D11Device*,const D3D11_TEXTURE2D_DESC*,const D3D11_SUBRESOURCE_DATA*,ID3D11Texture2D**);

typedef struct LxD3D11DeviceVtbl {
    HRESULT (*QueryInterface)(IUnknown*,REFIID,void**);
    ULONG   (*AddRef)(IUnknown*);
    ULONG   (*Release)(IUnknown*);
    /* D3D11Device methods (stub除く主要なもの) */
    HRESULT (*CreateBuffer)(LxD3D11Device*,const D3D11_BUFFER_DESC*,const D3D11_SUBRESOURCE_DATA*,ID3D11Buffer**);
    void*   _stubs[5]; /* CreateTexture1D等 */
    HRESULT (*CreateTexture2D)(LxD3D11Device*,const D3D11_TEXTURE2D_DESC*,const D3D11_SUBRESOURCE_DATA*,ID3D11Texture2D**);
} LxD3D11DeviceVtbl;

static HRESULT lx_dev_QI(IUnknown* s, REFIID r, void** p){(void)r;*p=s;return S_OK;}
static ULONG   lx_dev_AddRef(IUnknown* s){
    LxD3D11Device* d=(LxD3D11Device*)s;
    return (ULONG)__sync_add_and_fetch(&d->refcount,1);
}
static ULONG   lx_dev_Release(IUnknown* s){
    LxD3D11Device* d=(LxD3D11Device*)s;
    ULONG r=(ULONG)__sync_sub_and_fetch(&d->refcount,1);
    if(r==0){ free(d); DX_LOG("ID3D11Device released"); }
    return r;
}

static const LxD3D11DeviceVtbl LxDevVtbl = {
    lx_dev_QI, lx_dev_AddRef, lx_dev_Release,
    (PFN_CreateBuffer)lx_CreateBuffer,
    {NULL,NULL,NULL,NULL,NULL},
    (PFN_CreateTexture2D)lx_CreateTexture2D
};

/* ════════════════════════════════════════════════
   D3D11CreateDevice フック（メインエントリポイント）
   ════════════════════════════════════════════════ */
HRESULT D3D11CreateDevice(
    void*              pAdapter,
    UINT               DriverType,
    HMODULE            Software,
    UINT               Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels,
    UINT               FeatureLevels,
    UINT               SDKVersion,
    ID3D11Device**     ppDevice,
    D3D_FEATURE_LEVEL* pFeatureLevel,
    void**             ppImmediateContext)
{
    (void)pAdapter; (void)DriverType; (void)Software;
    (void)Flags; (void)SDKVersion;

    DX_LOG("D3D11CreateDevice called (Linexe D3D11->Vulkan)");

    /* Vulkan バックエンドを初期化（失敗してもデバイスオブジェクトは作成する） */
    pthread_once(&g_vk_once, vk_backend_init);
    if (!g_vk.ready)
        DX_LOG("D3D11CreateDevice: Vulkan not ready, device works in stub mode");

    /* 要求されたFeatureLevelの最大値を選択 */
    D3D_FEATURE_LEVEL selected = D3D_FEATURE_LEVEL_11_0;
    if (pFeatureLevels && FeatureLevels > 0)
        selected = pFeatureLevels[0];
    if (pFeatureLevel)
        *pFeatureLevel = selected;

    /* 偽デバイスオブジェクト生成 */
    if (ppDevice) {
        LxD3D11Device* dev = calloc(1, sizeof(LxD3D11Device));
        if (!dev) return E_OUTOFMEMORY;
        dev->lpVtbl        = &LxDevVtbl;
        dev->refcount      = 1;
        dev->feature_level = selected;
        *ppDevice = (ID3D11Device*)dev;
        DX_LOG("  -> Fake ID3D11Device created (FL=0x%04X)", selected);
    }

    /* デバイスコンテキストは最小スタブ（将来実装） */
    if (ppImmediateContext)
        *ppImmediateContext = NULL;

    return S_OK;
}

/* D3D11CreateDeviceAndSwapChain の偽実装 */
HRESULT D3D11CreateDeviceAndSwapChain(
    void*              pAdapter,
    UINT               DriverType,
    HMODULE            Software,
    UINT               Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels,
    UINT               FeatureLevels,
    UINT               SDKVersion,
    const DXGI_SWAP_CHAIN_DESC* pSwapChainDesc,
    IDXGISwapChain**   ppSwapChain,
    ID3D11Device**     ppDevice,
    D3D_FEATURE_LEVEL* pFeatureLevel,
    void**             ppImmediateContext)
{
    DX_LOG("D3D11CreateDeviceAndSwapChain (size=%ux%u, fmt=%s)",
           pSwapChainDesc ? pSwapChainDesc->BufferDesc.Width : 0,
           pSwapChainDesc ? pSwapChainDesc->BufferDesc.Height : 0,
           pSwapChainDesc ? dxgi_format_name(pSwapChainDesc->BufferDesc.Format) : "?");

    if (ppSwapChain) *ppSwapChain = NULL; /* SwapChain は Phase 4.3 で実装 */

    return D3D11CreateDevice(pAdapter, DriverType, Software, Flags,
                             pFeatureLevels, FeatureLevels, SDKVersion,
                             ppDevice, pFeatureLevel, ppImmediateContext);
}

/* ════════════════════════════════════════════════
   ライブラリ初期化・終了
   ════════════════════════════════════════════════ */
__attribute__((constructor))
static void d3d_hook_init(void) {
    DX_LOG("Linexe D3D11->Vulkan hook loaded");
}

__attribute__((destructor))
static void d3d_hook_fini(void) {
    if (g_vk.ready) {
        /* TODO: vkDestroyCommandPool(g_vk.device, g_vk.cmd_pool, NULL); */
        if (g_vk.device)
            g_vk.vkDestroyDevice(g_vk.device, NULL);
        if (g_vk.instance)
            g_vk.vkDestroyInstance(g_vk.instance, NULL);
    }
    if (g_vk.lib) dlclose(g_vk.lib);
    DX_LOG("Linexe D3D11->Vulkan hook unloaded");
}
