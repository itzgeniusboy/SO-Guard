# SO-Protector

> Native Android `.so` (ELF shared object) protection toolkit for developers protecting their own SDK and tool binaries in Termux on Android.

## How It Works

1. **Compress & Encrypt**: The target `.so` binary is compressed via Zstandard (preset 19) or LZMA and encrypted using AES-256-GCM with a per-build PBKDF2-HMAC-SHA256 derived key and 96-bit nonce.
2. **Link via `objcopy`**: The encrypted payload is embedded directly into an object file using `ld -b binary` (`_binary_payload_enc_start`), keeping source code free of plaintext arrays.
3. **In-Memory Loader Stub**: The loader stub (`stub/loader.c`) decrypts payload bytes at runtime into anonymous memory (`mmap` + `mprotect`), executing segment loading without writing decrypted ELF files to disk.
4. **Anti-Analysis & Environment Threads**: Spawns background threads periodically monitoring `/proc/self/status` `TracerPid`, `ptrace(PTRACE_TRACEME)`, timing delays, open debugger ports, root binaries (`su`, Magisk), QEMU/emulator build props, Frida artifacts (`frida-agent`), stealth threads (`gum-js-loop`, `gmain`), and inotify maps modifications.
5. **Continuous Integrity Re-Verification**: Spawns a background thread that periodically re-hashes the live `.text` segment against the build-time SHA-256 checksum to detect runtime memory patches or inline hooks.

---

## Protection Layers

- **Root & Emulator Detection (`stub/anti_env.c`)**:
  - Detects `su` binaries (`/system/bin/su`, `/sbin/su`), Magisk paths (`/data/adb/magisk`), `test-keys` build tags, and writable `/system` partition mounts.
  - Detects QEMU pipes (`/dev/qemu_pipe`), emulator build fingerprint properties (`sdk_gphone`, `goldfish`, `ranchu`), and hypervisor CPU flags in `/proc/cpuinfo`.
  - Detection triggers silent state corruption (`g_state_corrupted`) rather than immediate process exits, causing payload decryption to silently fail into garbage data.
- **OLLVM Control Flow Flattening (`modules/stub_builder.py`)**:
  - Supports OLLVM-patched Clang via `--ollvm-path`.
  - Passes `-mllvm -fla` (control flow flattening), `-mllvm -sub` (instruction substitution), `-mllvm -bcf` (bogus control flow), and `-mllvm -bcf_prob=70` to anti-debug, anti-hook, anti-env, and loader modules.
- **Frida Stealth Detection (`stub/anti_hook.c`)**:
  - Scans `/proc/self/task/*/comm` for Frida internal threads (`gum-js-loop`, `gmain`, `gdbus`).
  - Utilizes `inotify` watches on `/proc/self/maps` and `/proc/self/status` to detect late-injected libraries and gadget hooks.
- **Continuous Runtime Integrity (`stub/loader.c` & `modules/integrity.py`)**:
  - Periodically re-calculates `.text` section SHA-256 checksum in a dedicated thread to guard against runtime inline patching.
- **Whitebox AES Key Handling (`modules/whitebox.py`)**:
  - Optional `--whitebox` flag generates Chow et al. lookup-table whitebox AES transformations, preventing raw key material from existing in plaintext RAM.

---

## Repository Structure

```
.
├── protect.py          # Main CLI entry point
├── modules/
│   ├── __init__.py
│   ├── packer.py        # Compression & AES-256-GCM encryption
│   ├── keygen.py         # PBKDF2 key derivation & HWID binding
│   ├── stub_builder.py   # String encryption, OLLVM integration & NDK compilation
│   ├── integrity.py      # .text section SHA-256 self-checksum verification
│   └── whitebox.py       # Chow et al. lookup-table Whitebox AES generator
├── stub/
│   ├── loader.c         # Dynamic in-memory payload loader & integrity thread
│   ├── anti_debug.c     # TracerPid, ptrace, timing, and port scanners
│   ├── anti_debug.h
│   ├── anti_hook.c      # Frida stealth threads, inotify maps, & hook checks
│   ├── anti_hook.h
│   ├── anti_env.c       # Root & emulator environment detection
│   ├── anti_env.h
│   ├── string_crypt.h   # Compile-time string obfuscation macros
│   └── CMakeLists.txt   # CMake build configuration for stub
├── config.yaml          # Default build & protection configuration
├── requirements.txt    # Python dependencies (cryptography, rich, pyyaml, etc.)
├── .gitignore          # Python build artifact ignore rules
└── README.md           # Documentation
```

---

## Termux Installation Steps

1. **Install required Termux system packages**:
   ```bash
   pkg update && pkg install clang python git libzstd
   ```

2. **Clone repository and install Python dependencies**:
   ```bash
   git clone https://github.com/your-repo/so-protector.git
   cd so-protector
   pip install -r requirements.txt --break-system-packages
   ```

3. **Configure Android NDK toolchain**:
   Download the Android NDK for Linux/ARM64 and set the environment variable:
   ```bash
   export ANDROID_NDK_HOME=/path/to/android-ndk-r25c
   ```

4. **(Optional) OLLVM Setup**:
   To enable control flow flattening, build or obtain an OLLVM-patched Clang toolchain (e.g. from the [OLLVM Fork](https://github.com/heroims/obfuscator)) targeting aarch64 Android NDK, and pass `--ollvm-path /path/to/ollvm-clang` during build.

---

## CLI Usage

### 1. Generate Per-Build Keys (`keygen`)
Generates random AES-256 keys and nonces stored securely in `./keys/` (gitignored):
```bash
python protect.py keygen
```

Optionally bind derived keys to a specific HWID string:
```bash
python protect.py keygen --bind-hwid "DEVICE_HWID_ABC123"
```

### 2. Build Protected `.so` Binary (`build`)
Pack, encrypt, and compile the loader stub with advanced protection options:
```bash
python protect.py build input_lib.so --output protected_lib.so --level 3 --ollvm-path /path/to/ollvm-clang --whitebox
```

**Options**:
- `--output`, `-o`: Specify output `.so` filename.
- `--ndk-path`: Path to NDK toolchain root directory.
- `--ollvm-path`: Path to OLLVM-patched Clang compiler binary.
- `--whitebox`: Enable Chow et al. lookup-table Whitebox AES key handling.
- `--level`, `-l`: Protection level:
  - `1`: Compression + AES-256-GCM encryption only
  - `2`: Level 1 + Anti-debugging & anti-environment background threads
  - `3`: Level 2 + Anti-hooking (Frida stealth threads/inotify) + continuous `.text` self-integrity re-verification
- `--bind-hwid`: Bind stub decryption key to target HWID string.

### 3. Verify Protected Binary (`verify`)
Perform a sanity check on the output binary:
```bash
python protect.py verify protected_lib.so
```

---

## Limitations

This protection suite significantly increases the time, effort, and technical skill required for casual reverse engineering by stripping debug symbols, encrypting native payloads, obfuscating strings, and continuously checking execution environments.

However, **it is not unbreakable**:
- Experienced reverse engineers equipped with custom Android kernels, eBPF dynamic memory inspection, hardware breakpoints, or advanced decompilers (IDA Pro / Ghidra) can dump memory regions after payload decryption occurs in RAM.

---

## License

MIT License
