/*
 * Linexe - DirectX Type Definitions (Phase 4)
 * Licensed under Apache License 2.0
 *
 * DirectX 11 / DXGI の最小限の型定義。
 * Windows SDK不要で使えるよう自前定義する。
 *
 * 参考: Microsoft DirectX 11 SDK Documentation
 *       DXVK (https://github.com/doitsujin/dxvk)
 */

#ifndef LINEXE_DX_TYPES_H
#define LINEXE_DX_TYPES_H

#include <stdint.h>
#include <stddef.h>

/* ════════════════════════════════════════════════
   基本型
   ════════════════════════════════════════════════ */
typedef unsigned int   UINT;
typedef int            INT;
typedef unsigned long  ULONG;
typedef long           LONG;
typedef int            BOOL;
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned int   DWORD;
typedef int64_t        LONGLONG;
typedef uint64_t       ULONGLONG;
typedef float          FLOAT;
typedef void*          LPVOID;
typedef const void*    LPCVOID;
typedef const char*    LPCSTR;
typedef const wchar_t* LPCWSTR;
typedef long           HRESULT;
typedef void*          HANDLE;
typedef void*          HWND;
typedef void*          HMODULE;
typedef void*          REFIID;
typedef uint64_t       SIZE_T;

/* HRESULT コード */
#define S_OK                   0x00000000L
#define S_FALSE                0x00000001L
#define E_NOTIMPL              0x80004001L
#define E_NOINTERFACE          0x80004002L
#define E_POINTER              0x80004003L
#define E_ABORT                0x80004004L
#define E_FAIL                 0x80004005L
#define E_INVALIDARG           0x80000003L
#define E_OUTOFMEMORY          0x8007000EL
#define DXGI_ERROR_NOT_FOUND   0x887A0002L
#define DXGI_ERROR_UNSUPPORTED 0x887A0004L
#define D3D11_ERROR_TOO_MANY_UNIQUE_STATE_OBJECTS 0x88790001L

#define SUCCEEDED(hr) ((HRESULT)(hr) >= 0)
#define FAILED(hr)    ((HRESULT)(hr) < 0)

/* ════════════════════════════════════════════════
   DXGI 型定義
   ════════════════════════════════════════════════ */

/* DXGI フォーマット（主要なもの） */
typedef enum DXGI_FORMAT {
    DXGI_FORMAT_UNKNOWN                  = 0,
    DXGI_FORMAT_R32G32B32A32_FLOAT       = 2,
    DXGI_FORMAT_R32G32B32A32_UINT        = 3,
    DXGI_FORMAT_R32G32B32_FLOAT          = 6,
    DXGI_FORMAT_R16G16B16A16_FLOAT       = 10,
    DXGI_FORMAT_R16G16B16A16_UNORM       = 11,
    DXGI_FORMAT_R32G32_FLOAT             = 16,
    DXGI_FORMAT_R32G32_UINT              = 17,
    DXGI_FORMAT_R8G8B8A8_UNORM           = 28,
    DXGI_FORMAT_R8G8B8A8_UNORM_SRGB      = 29,
    DXGI_FORMAT_R8G8B8A8_UINT            = 30,
    DXGI_FORMAT_R32_FLOAT                = 41,
    DXGI_FORMAT_R32_UINT                 = 42,
    DXGI_FORMAT_R32_SINT                 = 43,
    DXGI_FORMAT_D32_FLOAT                = 40,
    DXGI_FORMAT_D24_UNORM_S8_UINT        = 45,
    DXGI_FORMAT_D16_UNORM                = 55,
    DXGI_FORMAT_R16_FLOAT                = 54,
    DXGI_FORMAT_R16_UINT                 = 57,
    DXGI_FORMAT_R8_UNORM                 = 61,
    DXGI_FORMAT_B8G8R8A8_UNORM           = 87,
    DXGI_FORMAT_B8G8R8A8_UNORM_SRGB      = 91,
    DXGI_FORMAT_BC1_UNORM                = 71,
    DXGI_FORMAT_BC3_UNORM                = 77,
    DXGI_FORMAT_BC5_UNORM                = 83,
    DXGI_FORMAT_BC7_UNORM                = 98,
} DXGI_FORMAT;

/* DXGI スワップチェイン記述子 */
typedef struct DXGI_SWAP_CHAIN_DESC {
    struct {
        UINT   Width;
        UINT   Height;
        struct { UINT Numerator; UINT Denominator; } RefreshRate;
        DXGI_FORMAT Format;
        struct { UINT Count; UINT Quality; } SampleDesc;
        UINT   ScanlineOrdering;
        UINT   Scaling;
    } BufferDesc;
    struct { UINT Count; UINT Quality; } SampleDesc;
    UINT   BufferUsage;
    UINT   BufferCount;
    HWND   OutputWindow;
    BOOL   Windowed;
    UINT   SwapEffect;
    UINT   Flags;
} DXGI_SWAP_CHAIN_DESC;

/* ════════════════════════════════════════════════
   D3D11 型定義
   ════════════════════════════════════════════════ */

/* D3D_FEATURE_LEVEL */
typedef enum D3D_FEATURE_LEVEL {
    D3D_FEATURE_LEVEL_9_1  = 0x9100,
    D3D_FEATURE_LEVEL_9_2  = 0x9200,
    D3D_FEATURE_LEVEL_9_3  = 0x9300,
    D3D_FEATURE_LEVEL_10_0 = 0xa000,
    D3D_FEATURE_LEVEL_10_1 = 0xa100,
    D3D_FEATURE_LEVEL_11_0 = 0xb000,
    D3D_FEATURE_LEVEL_11_1 = 0xb100,
    D3D_FEATURE_LEVEL_12_0 = 0xc000,
    D3D_FEATURE_LEVEL_12_1 = 0xc100,
} D3D_FEATURE_LEVEL;

/* D3D11_USAGE */
typedef enum D3D11_USAGE {
    D3D11_USAGE_DEFAULT   = 0,
    D3D11_USAGE_IMMUTABLE = 1,
    D3D11_USAGE_DYNAMIC   = 2,
    D3D11_USAGE_STAGING   = 3,
} D3D11_USAGE;

/* D3D11_BIND_FLAG */
typedef enum D3D11_BIND_FLAG {
    D3D11_BIND_VERTEX_BUFFER   = 0x0001,
    D3D11_BIND_INDEX_BUFFER    = 0x0002,
    D3D11_BIND_CONSTANT_BUFFER = 0x0004,
    D3D11_BIND_SHADER_RESOURCE = 0x0008,
    D3D11_BIND_STREAM_OUTPUT   = 0x0010,
    D3D11_BIND_RENDER_TARGET   = 0x0020,
    D3D11_BIND_DEPTH_STENCIL   = 0x0040,
    D3D11_BIND_UNORDERED_ACCESS= 0x0080,
} D3D11_BIND_FLAG;

/* D3D11_CPU_ACCESS_FLAG */
typedef enum D3D11_CPU_ACCESS_FLAG {
    D3D11_CPU_ACCESS_WRITE = 0x10000,
    D3D11_CPU_ACCESS_READ  = 0x20000,
} D3D11_CPU_ACCESS_FLAG;

/* D3D11_MAP */
typedef enum D3D11_MAP {
    D3D11_MAP_READ              = 1,
    D3D11_MAP_WRITE             = 2,
    D3D11_MAP_READ_WRITE        = 3,
    D3D11_MAP_WRITE_DISCARD     = 4,
    D3D11_MAP_WRITE_NO_OVERWRITE= 5,
} D3D11_MAP;

/* D3D11_PRIMITIVE_TOPOLOGY */
typedef enum D3D_PRIMITIVE_TOPOLOGY {
    D3D_PRIMITIVE_TOPOLOGY_UNDEFINED         = 0,
    D3D_PRIMITIVE_TOPOLOGY_POINTLIST         = 1,
    D3D_PRIMITIVE_TOPOLOGY_LINELIST          = 2,
    D3D_PRIMITIVE_TOPOLOGY_LINESTRIP         = 3,
    D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST      = 4,
    D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP     = 5,
} D3D_PRIMITIVE_TOPOLOGY;

/* D3D11_BUFFER_DESC */
typedef struct D3D11_BUFFER_DESC {
    UINT ByteWidth;
    UINT Usage;
    UINT BindFlags;
    UINT CPUAccessFlags;
    UINT MiscFlags;
    UINT StructureByteStride;
} D3D11_BUFFER_DESC;

/* D3D11_TEXTURE2D_DESC */
typedef struct D3D11_TEXTURE2D_DESC {
    UINT        Width;
    UINT        Height;
    UINT        MipLevels;
    UINT        ArraySize;
    DXGI_FORMAT Format;
    struct { UINT Count; UINT Quality; } SampleDesc;
    UINT        Usage;
    UINT        BindFlags;
    UINT        CPUAccessFlags;
    UINT        MiscFlags;
} D3D11_TEXTURE2D_DESC;

/* D3D11_SUBRESOURCE_DATA */
typedef struct D3D11_SUBRESOURCE_DATA {
    const void* pSysMem;
    UINT        SysMemPitch;
    UINT        SysMemSlicePitch;
} D3D11_SUBRESOURCE_DATA;

/* D3D11_MAPPED_SUBRESOURCE */
typedef struct D3D11_MAPPED_SUBRESOURCE {
    void* pData;
    UINT  RowPitch;
    UINT  DepthPitch;
} D3D11_MAPPED_SUBRESOURCE;

/* D3D11_VIEWPORT */
typedef struct D3D11_VIEWPORT {
    FLOAT TopLeftX;
    FLOAT TopLeftY;
    FLOAT Width;
    FLOAT Height;
    FLOAT MinDepth;
    FLOAT MaxDepth;
} D3D11_VIEWPORT;

/* D3D11_RECT */
typedef struct D3D11_RECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} D3D11_RECT;

/* D3D11_BLEND / D3D11_BLEND_OP */
typedef enum D3D11_BLEND {
    D3D11_BLEND_ZERO        = 1,
    D3D11_BLEND_ONE         = 2,
    D3D11_BLEND_SRC_ALPHA   = 5,
    D3D11_BLEND_INV_SRC_ALPHA = 6,
    D3D11_BLEND_DEST_ALPHA  = 7,
    D3D11_BLEND_INV_DEST_ALPHA = 8,
} D3D11_BLEND;

typedef enum D3D11_BLEND_OP {
    D3D11_BLEND_OP_ADD         = 1,
    D3D11_BLEND_OP_SUBTRACT    = 2,
    D3D11_BLEND_OP_REV_SUBTRACT= 3,
    D3D11_BLEND_OP_MIN         = 4,
    D3D11_BLEND_OP_MAX         = 5,
} D3D11_BLEND_OP;

/* D3D11_BLEND_DESC */
typedef struct D3D11_BLEND_DESC {
    BOOL AlphaToCoverageEnable;
    BOOL IndependentBlendEnable;
    struct {
        BOOL      BlendEnable;
        UINT      SrcBlend;
        UINT      DestBlend;
        UINT      BlendOp;
        UINT      SrcBlendAlpha;
        UINT      DestBlendAlpha;
        UINT      BlendOpAlpha;
        BYTE      RenderTargetWriteMask;
    } RenderTarget[8];
} D3D11_BLEND_DESC;

/* D3D11_DEPTH_STENCIL_DESC */
typedef struct D3D11_DEPTH_STENCIL_DESC {
    BOOL  DepthEnable;
    UINT  DepthWriteMask;
    UINT  DepthFunc;
    BOOL  StencilEnable;
    BYTE  StencilReadMask;
    BYTE  StencilWriteMask;
    struct { UINT StencilFailOp; UINT StencilDepthFailOp; UINT StencilPassOp; UINT StencilFunc; }
          FrontFace, BackFace;
} D3D11_DEPTH_STENCIL_DESC;

/* D3D11_RASTERIZER_DESC */
typedef struct D3D11_RASTERIZER_DESC {
    UINT  FillMode;
    UINT  CullMode;
    BOOL  FrontCounterClockwise;
    INT   DepthBias;
    FLOAT DepthBiasClamp;
    FLOAT SlopeScaledDepthBias;
    BOOL  DepthClipEnable;
    BOOL  ScissorEnable;
    BOOL  MultisampleEnable;
    BOOL  AntialiasedLineEnable;
} D3D11_RASTERIZER_DESC;

/* D3D11_INPUT_ELEMENT_DESC */
typedef struct D3D11_INPUT_ELEMENT_DESC {
    LPCSTR    SemanticName;
    UINT      SemanticIndex;
    DXGI_FORMAT Format;
    UINT      InputSlot;
    UINT      AlignedByteOffset;
    UINT      InputSlotClass;
    UINT      InstanceDataStepRate;
} D3D11_INPUT_ELEMENT_DESC;

/* D3D11_SHADER_RESOURCE_VIEW_DESC */
typedef struct D3D11_SHADER_RESOURCE_VIEW_DESC {
    DXGI_FORMAT Format;
    UINT        ViewDimension;
    union {
        struct { UINT MostDetailedMip; UINT MipLevels; } Texture2D;
        struct { UINT FirstElement; UINT NumElements; } Buffer;
    };
} D3D11_SHADER_RESOURCE_VIEW_DESC;

/* D3D11_SAMPLER_DESC */
typedef struct D3D11_SAMPLER_DESC {
    UINT  Filter;
    UINT  AddressU;
    UINT  AddressV;
    UINT  AddressW;
    FLOAT MipLODBias;
    UINT  MaxAnisotropy;
    UINT  ComparisonFunc;
    FLOAT BorderColor[4];
    FLOAT MinLOD;
    FLOAT MaxLOD;
} D3D11_SAMPLER_DESC;

/* ════════════════════════════════════════════════
   IUnknown (COM基底インターフェース)
   ════════════════════════════════════════════════ */
typedef struct IUnknown IUnknown;
typedef struct IUnknownVtbl {
    HRESULT (*QueryInterface)(IUnknown*, REFIID, void**);
    ULONG   (*AddRef)(IUnknown*);
    ULONG   (*Release)(IUnknown*);
} IUnknownVtbl;
struct IUnknown { const IUnknownVtbl* lpVtbl; };

/* ════════════════════════════════════════════════
   フォワード宣言（COMオブジェクト）
   ════════════════════════════════════════════════ */
typedef struct ID3D11Device           ID3D11Device;
typedef struct ID3D11DeviceContext    ID3D11DeviceContext;
typedef struct IDXGISwapChain         IDXGISwapChain;
typedef struct ID3D11Buffer           ID3D11Buffer;
typedef struct ID3D11Texture2D        ID3D11Texture2D;
typedef struct ID3D11RenderTargetView ID3D11RenderTargetView;
typedef struct ID3D11DepthStencilView ID3D11DepthStencilView;
typedef struct ID3D11ShaderResourceView ID3D11ShaderResourceView;
typedef struct ID3D11VertexShader     ID3D11VertexShader;
typedef struct ID3D11PixelShader      ID3D11PixelShader;
typedef struct ID3D11GeometryShader   ID3D11GeometryShader;
typedef struct ID3D11ComputeShader    ID3D11ComputeShader;
typedef struct ID3D11InputLayout      ID3D11InputLayout;
typedef struct ID3D11BlendState       ID3D11BlendState;
typedef struct ID3D11DepthStencilState ID3D11DepthStencilState;
typedef struct ID3D11RasterizerState  ID3D11RasterizerState;
typedef struct ID3D11SamplerState     ID3D11SamplerState;

/* ════════════════════════════════════════════════
   DXGI Format → Vulkan Format 変換テーブル
   ════════════════════════════════════════════════ */
typedef struct {
    DXGI_FORMAT dx_fmt;
    int         vk_fmt;   /* VkFormat (vulkan.h の値) */
    const char* name;
} DX_VK_FORMAT_MAP;

/* VkFormat 主要値（vulkan.h不要のための定義） */
#define VK_FORMAT_UNDEFINED               0
#define VK_FORMAT_R8G8B8A8_UNORM         37
#define VK_FORMAT_R8G8B8A8_SRGB          43
#define VK_FORMAT_B8G8R8A8_UNORM         44
#define VK_FORMAT_B8G8R8A8_SRGB          50
#define VK_FORMAT_R16G16B16A16_SFLOAT    97
#define VK_FORMAT_R16G16B16A16_UNORM     91
#define VK_FORMAT_R32G32B32A32_SFLOAT   109
#define VK_FORMAT_R32G32B32A32_UINT     107
#define VK_FORMAT_R32G32B32_SFLOAT       106
#define VK_FORMAT_R32G32_SFLOAT          103
#define VK_FORMAT_R32G32_UINT            101
#define VK_FORMAT_R32_SFLOAT              98
#define VK_FORMAT_R32_UINT                98
#define VK_FORMAT_R32_SINT               100
#define VK_FORMAT_D32_SFLOAT             126
#define VK_FORMAT_D24_UNORM_S8_UINT      129
#define VK_FORMAT_D16_UNORM              124
#define VK_FORMAT_R16_SFLOAT              76
#define VK_FORMAT_R16_UINT                74
#define VK_FORMAT_R8_UNORM                9
#define VK_FORMAT_BC1_RGB_UNORM_BLOCK    131
#define VK_FORMAT_BC3_UNORM_BLOCK        137
#define VK_FORMAT_BC5_UNORM_BLOCK        141
#define VK_FORMAT_BC7_UNORM_BLOCK        145

static const DX_VK_FORMAT_MAP DX_FORMAT_TABLE[] = {
    { DXGI_FORMAT_R8G8B8A8_UNORM,      VK_FORMAT_R8G8B8A8_UNORM,         "RGBA8_UNORM"       },
    { DXGI_FORMAT_R8G8B8A8_UNORM_SRGB, VK_FORMAT_R8G8B8A8_SRGB,          "RGBA8_SRGB"        },
    { DXGI_FORMAT_B8G8R8A8_UNORM,      VK_FORMAT_B8G8R8A8_UNORM,         "BGRA8_UNORM"       },
    { DXGI_FORMAT_B8G8R8A8_UNORM_SRGB, VK_FORMAT_B8G8R8A8_SRGB,          "BGRA8_SRGB"        },
    { DXGI_FORMAT_R16G16B16A16_FLOAT,  VK_FORMAT_R16G16B16A16_SFLOAT,    "RGBA16_FLOAT"      },
    { DXGI_FORMAT_R16G16B16A16_UNORM,  VK_FORMAT_R16G16B16A16_UNORM,     "RGBA16_UNORM"      },
    { DXGI_FORMAT_R32G32B32A32_FLOAT,  VK_FORMAT_R32G32B32A32_SFLOAT,    "RGBA32_FLOAT"      },
    { DXGI_FORMAT_R32G32B32A32_UINT,   VK_FORMAT_R32G32B32A32_UINT,      "RGBA32_UINT"       },
    { DXGI_FORMAT_R32G32B32_FLOAT,     VK_FORMAT_R32G32B32_SFLOAT,       "RGB32_FLOAT"       },
    { DXGI_FORMAT_R32G32_FLOAT,        VK_FORMAT_R32G32_SFLOAT,          "RG32_FLOAT"        },
    { DXGI_FORMAT_R32G32_UINT,         VK_FORMAT_R32G32_UINT,            "RG32_UINT"         },
    { DXGI_FORMAT_R32_FLOAT,           VK_FORMAT_R32_SFLOAT,             "R32_FLOAT"         },
    { DXGI_FORMAT_R32_UINT,            VK_FORMAT_R32_UINT,               "R32_UINT"          },
    { DXGI_FORMAT_R32_SINT,            VK_FORMAT_R32_SINT,               "R32_SINT"          },
    { DXGI_FORMAT_D32_FLOAT,           VK_FORMAT_D32_SFLOAT,             "D32_FLOAT"         },
    { DXGI_FORMAT_D24_UNORM_S8_UINT,   VK_FORMAT_D24_UNORM_S8_UINT,      "D24S8"             },
    { DXGI_FORMAT_D16_UNORM,           VK_FORMAT_D16_UNORM,              "D16"               },
    { DXGI_FORMAT_R16_FLOAT,           VK_FORMAT_R16_SFLOAT,             "R16_FLOAT"         },
    { DXGI_FORMAT_R16_UINT,            VK_FORMAT_R16_UINT,               "R16_UINT"          },
    { DXGI_FORMAT_R8_UNORM,            VK_FORMAT_R8_UNORM,               "R8_UNORM"          },
    { DXGI_FORMAT_BC1_UNORM,           VK_FORMAT_BC1_RGB_UNORM_BLOCK,    "BC1_UNORM"         },
    { DXGI_FORMAT_BC3_UNORM,           VK_FORMAT_BC3_UNORM_BLOCK,        "BC3_UNORM"         },
    { DXGI_FORMAT_BC5_UNORM,           VK_FORMAT_BC5_UNORM_BLOCK,        "BC5_UNORM"         },
    { DXGI_FORMAT_BC7_UNORM,           VK_FORMAT_BC7_UNORM_BLOCK,        "BC7_UNORM"         },
    { DXGI_FORMAT_UNKNOWN,             VK_FORMAT_UNDEFINED,              "UNKNOWN"           },
};
#define DX_FORMAT_TABLE_LEN (sizeof(DX_FORMAT_TABLE)/sizeof(DX_FORMAT_TABLE[0]))

static inline int dxgi_to_vk_format(DXGI_FORMAT dx) {
    for (size_t i = 0; i < DX_FORMAT_TABLE_LEN; i++)
        if (DX_FORMAT_TABLE[i].dx_fmt == dx)
            return DX_FORMAT_TABLE[i].vk_fmt;
    return VK_FORMAT_UNDEFINED;
}

static inline const char* dxgi_format_name(DXGI_FORMAT dx) {
    for (size_t i = 0; i < DX_FORMAT_TABLE_LEN; i++)
        if (DX_FORMAT_TABLE[i].dx_fmt == dx)
            return DX_FORMAT_TABLE[i].name;
    return "UNKNOWN";
}

#endif /* LINEXE_DX_TYPES_H */
