# Linexe

A high-level Windows EXE compatibility layer for Linux (Zorin OS 18).

> More powerful than Wine. Built from scratch.

## Features (planned)

- PE Loader — parse and map EXE into memory
- Windows API emulation — "You're on Windows 10!"
- Syscall translation engine — NT syscalls → Linux syscalls
- DirectX → Vulkan bridge
- Anti-cheat support via KVM hybrid mode

## Build

```bash
gcc -o linexe src/pe_loader.c
./linexe yourapp.exe
```

## License

Apache License 2.0 — see [LICENSE](./LICENSE) for details.

> ⚠️ 二次配布物に含まれるウイルス・マルウェア等について、原作者は一切の責任を負いません。
