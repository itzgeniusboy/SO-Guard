# SO-Protector

An Android ELF Shared Object (`.so`) compression, encryption, and runtime-loader protection suite designed to run in Termux on Android.

## Features

- **Level 1**: Zstandard/LZMA compression + AES-256-GCM encryption of target native `.so` binaries.
- **Level 2**: Level 1 + Active anti-debugging background threads (`TracerPid`, `PTRACE_TRACEME`, timing single-step checks, debugger port scanning).
- **Level 3**: Level 2 + Anti-hooking mechanisms (Frida agent/gadget detection, open Frida ports, anonymous executable memory region scans) + `.text` segment SHA-256 self-integrity verification.
- **HWID Binding**: Option to XOR-bind derived build keys to a target device HWID hash.
- **Embedded Payload**: Binary payloads linked directly via `ld -b binary` object files, preventing source string leakage.
- **String Obfuscation**: Compile-time string encryption pass (`string_crypt.h` & `stub_builder.py`) removing plaintext error messages and proc paths.

---

## Installation in Termux (Android)

1. **Install core packages**:
   ```bash
   pkg update && pkg install clang python libzstd
   pip install -r requirements.txt
   ```

2. **Setup Android NDK**:
   Download and unpack the Android NDK for Linux/Android ARM64, then export its path:
   ```bash
   export ANDROID_NDK_HOME=/path/to/android-ndk-r25c
   ```

---

## Usage

### 1. Build a Protected `.so` Binary
```bash
python protect.py build libnative.so --output libprotected.so --level 3
```

With HWID binding:
```bash
python protect.py build libnative.so --bind-hwid "ANDROID_DEVICE_HWID_12345"
```

### 2. Verify Output Binary
```bash
python protect.py verify libprotected.so
```

### 3. Generate Standalone Build Keys
```bash
python protect.py keygen
```

---

## Honest Limitations & Disclaimer

This tool raises the barrier to casual reverse engineering and analysis by wrapping native Android `.so` shared objects in an encrypted in-memory loader stub with active anti-analysis heuristics. 

However, **it is not unbreakable**:
- A skilled reverse engineer with root access, kernel-level tracing (e.g., custom Android kernels or eBPF), hardware breakpoints, or advanced disassembly suites (IDA Pro, Ghidra) can memory-dump the decrypted payload after segment mapping.
- Designed strictly for developers protecting their proprietary SDK binaries against casual inspection.
