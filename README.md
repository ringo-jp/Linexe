# Linexe

<div align="center">

**A high-level Windows EXE compatibility layer for Linux**
**Linux上でWindowsのEXEを動かす、高水準互換レイヤー**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-green.svg)]()
[![Phase](https://img.shields.io/badge/Phase-2%2F5-orange.svg)]()
[![Language](https://img.shields.io/badge/Language-C-lightgrey.svg)]()

[English](#english) | [日本語](#japanese)

</div>

---

<a name="english"></a>
## 🇬🇧 English

### What is Linexe?

Linexe is a Windows EXE compatibility layer for Linux, built from scratch.
Unlike Wine, Linexe aims to be a higher-level, more transparent compatibility system — including support for kernel-driver-based anti-cheat software that Wine cannot handle.

**Target environment:** Zorin OS 18 (Ubuntu 24.04 base), x86-64

### How it works

```
[ EXE ]
   ↓  "Are you Windows?"
[ Spoof Layer ]  ←  "Yes! Windows 10 Pro, Build 19045!"
   ↓  Windows API / Syscall
[ Translation Engine ]  ←  converts to Linux syscalls
   ↓
[ Linux Kernel ]
```

Linexe intercepts Windows API calls at the shared-library level using `LD_PRELOAD`,
returning spoofed Windows environment data and transparently mapping Windows I/O to POSIX calls.

### Features

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | PE Loader — parse EXE headers, enumerate sections | ✅ Complete |
| 2 | Windows API spoof layer (`LD_PRELOAD` hook) | 🔧 In progress |
| 3 | Syscall translation engine (`ptrace`-based) | 📋 Planned |
| 4 | DirectX → Vulkan bridge | 📋 Planned |
| 5 | Anti-cheat support via KVM hybrid mode | 📋 Planned |

### Phase 2: Hooked APIs

| API | Purpose |
|-----|---------|
| `GetVersionExA/W` | Reports Windows 10.0.19045 |
| `RtlGetVersion` | Low-level OS version spoof (ntdll) |
| `VerifyVersionInfoA` | Forces version checks to return TRUE |
| `IsWow64Process` | Reports native 64-bit environment |
| `GetSystemInfo` | Spoof CPU arch as AMD64, 4 cores |
| `open` | Translates Windows paths to Linux paths |
| `mprotect` | Passthrough with logging |

### Build

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/Linexe.git
cd Linexe

# Build all components
make all

# Run tests
make test
```

### Usage

```bash
# Phase 1: Inspect an EXE file
./linexe yourapp.exe

# Phase 2: Hook layer — spoof Windows environment
LD_PRELOAD=./linexe_hook.so wine yourapp.exe

# Phase 2: API fake self-test (no EXE needed)
./api_test
```

**Example Phase 1 output:**
```
╔══════════════════════════════════════╗
║  Linexe  v0.1.0  -  Phase 1 Loader  ║
╚══════════════════════════════════════╝

[*] Target: notepad.exe

[*] MZ magic OK  (offset to PE: 0xF8)
[*] PE signature OK

── COFF Header ─────────────────────────
    Machine        : 0x8664 (x86-64)
    Sections       : 6

── Optional Header ─────────────────────
    ImageBase      : 0x0000000140000000
    EntryPoint RVA : 0x00012345
    Subsystem      : Windows GUI

── Sections ────────────────────────────
    Name      VirtAddr    VirtSize    RawSize     Perms
    ──────────────────────────────────────────────────
    .text     0x00001000  0x0001A000  0x0001A000  R-X
    .rdata    0x0001B000  0x00008000  0x00008000  R--
    .data     0x00023000  0x00002000  0x00001000  RW-
```

### Project Structure

```
Linexe/
├── README.md
├── LICENSE
├── Makefile
├── src/
│   ├── pe_loader.c    # Phase 1: PE header parser
│   ├── api_fake.c     # Phase 2: Windows API fake implementations
│   └── hook.c         # Phase 2: LD_PRELOAD hook layer
├── tests/
│   └── (test EXE files go here)
└── docs/
    └── design.md      # Technical design document
```

### Roadmap

**Phase 3 — Syscall Translation Engine**
Intercept Windows NT syscalls using `ptrace` or `seccomp-bpf` and translate them to Linux syscalls in real time.

**Phase 4 — DirectX → Vulkan**
Bridge DirectX 11/12 calls to Vulkan, similar to DXVK, enabling 3D game support.

**Phase 5 — Anti-cheat (KVM Hybrid)**
Run anti-cheat kernel drivers in a minimal Windows KVM guest while the game itself runs natively on Linux via Linexe.

```
┌──────────────────────────────────┐
│  Linux Host                      │
│  ┌────────────────────────────┐  │
│  │  KVM (minimal Windows)     │  │
│  │  Anti-cheat driver here    │  │
│  └────────────────────────────┘  │
│  Game runs here via Linexe       │
└──────────────────────────────────┘
```

### Contributing

Pull requests are welcome!
Please open an issue before submitting large changes.

### License

Apache License 2.0

> ⚠️ **Disclaimer:** The author takes no responsibility for viruses or malware included in redistributed versions of this software.

---

<a name="japanese"></a>
## 🇯🇵 日本語

### Linexeとは？

LinexeはLinux上でWindowsのEXEファイルを動かすための互換レイヤーです。ゼロから自作しています。
Wineより高水準・高透過を目指しており、Wineが対応できないカーネルドライバ型アンチチートへの対応も目標としています。

**対象環境：** Zorin OS 18（Ubuntu 24.04ベース）、x86-64

### 仕組み

```
[ EXE ]
   ↓  「お前、Windowsか？」
[ 偽装レイヤー ]  ←  「はい！Windows 10 Pro Build 19045です！」
   ↓  Windows API / Syscall
[ 変換エンジン ]  ←  Linux Syscallに翻訳
   ↓
[ Linux Kernel ]
```

`LD_PRELOAD` を使って共有ライブラリレベルでWindows APIを横取りし、
偽のWindowsバージョン情報を返しながらI/OをPOSIXに透過変換します。

### 機能一覧

| Phase | 内容 | 状態 |
|-------|------|------|
| 1 | PEローダー — EXEヘッダ解析・セクション列挙 | ✅ 完成 |
| 2 | Windows API偽装レイヤー（`LD_PRELOAD`フック） | 🔧 実装中 |
| 3 | Syscall変換エンジン（`ptrace`ベース） | 📋 予定 |
| 4 | DirectX → Vulkan変換 | 📋 予定 |
| 5 | アンチチート対応（KVMハイブリッド方式） | 📋 予定 |

### Phase 2：フック済みAPI一覧

| API | 内容 |
|-----|------|
| `GetVersionExA/W` | Windows 10.0.19045として偽装 |
| `RtlGetVersion` | ntdll経由の低レベルバージョン偽装 |
| `VerifyVersionInfoA` | バージョン確認を強制的にTRUEにする |
| `IsWow64Process` | 64bitネイティブ環境として偽装 |
| `GetSystemInfo` | CPUをAMD64・4コアとして偽装 |
| `open` | Windowsパスを自動でLinuxパスに変換 |
| `mprotect` | ログ付きでそのまま通過 |

### ビルド方法

```bash
# クローン
git clone https://github.com/YOUR_USERNAME/Linexe.git
cd Linexe

# 全コンポーネントをビルド
make all

# テスト実行
make test
```

### 使い方

```bash
# Phase 1：EXEファイルを解析する
./linexe yourapp.exe

# Phase 2：フックレイヤー — Windowsに見せかける
LD_PRELOAD=./linexe_hook.so wine yourapp.exe

# Phase 2：APIセルフテスト（EXE不要）
./api_test
```

**Phase 1 出力例：**
```
╔══════════════════════════════════════╗
║  Linexe  v0.1.0  -  Phase 1 Loader  ║
╚══════════════════════════════════════╝

[*] Target: notepad.exe

[*] MZ magic OK  (offset to PE: 0xF8)
[*] PE signature OK

── COFF Header ─────────────────────────
    Machine        : 0x8664 (x86-64)
    Sections       : 6

── Optional Header ─────────────────────
    ImageBase      : 0x0000000140000000
    EntryPoint RVA : 0x00012345
    Subsystem      : Windows GUI

── Sections ────────────────────────────
    Name      VirtAddr    VirtSize    RawSize     Perms
    ──────────────────────────────────────────────────
    .text     0x00001000  0x0001A000  0x0001A000  R-X
    .rdata    0x0001B000  0x00008000  0x00008000  R--
    .data     0x00023000  0x00002000  0x00001000  RW-
```

### プロジェクト構成

```
Linexe/
├── README.md
├── LICENSE
├── Makefile
├── src/
│   ├── pe_loader.c    # Phase 1: PEヘッダパーサー
│   ├── api_fake.c     # Phase 2: Windows API偽実装
│   └── hook.c         # Phase 2: LD_PRELOADフックレイヤー
├── tests/
│   └── （テスト用EXEをここに置く）
└── docs/
    └── design.md      # 技術設計書
```

### ロードマップ

**Phase 3 — Syscall変換エンジン**
`ptrace` または `seccomp-bpf` でWindows NTシステムコールをインターセプトし、
リアルタイムでLinuxシステムコールに変換します。

**Phase 4 — DirectX → Vulkan**
DirectX 11/12の呼び出しをVulkanにブリッジし、3Dゲームに対応します。

**Phase 5 — アンチチート対応（KVMハイブリッド）**
アンチチートのカーネルドライバだけを最小構成のKVM上Windowsで動かし、
ゲーム本体はLinux上のLinexeで動かすハイブリッド方式。

```
┌──────────────────────────────────┐
│  Linux ホスト                    │
│  ┌────────────────────────────┐  │
│  │  KVM（最小Windowsカーネル）  │  │
│  │  アンチチートドライバはここ  │  │
│  └────────────────────────────┘  │
│  ゲーム本体はLinexe経由でここで動く │
└──────────────────────────────────┘
```

### コントリビュート

プルリクエスト歓迎です。
大きな変更を加える前にIssueを立てていただけると助かります。

### ライセンス

Apache License 2.0

> ⚠️ **免責事項：** 二次配布物に含まれるウイルス・マルウェア等について、原作者は一切の責任を負いません。
