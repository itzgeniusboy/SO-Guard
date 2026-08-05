# SO-Protector

> Native Android `.so` (ELF shared object) protection toolkit for developers protecting their own SDK and tool binaries in Termux on Android.

## How It Works

1. **Compress & Encrypt**: The target `.so` binary is compressed via Zstandard (preset 19) or LZMA and encrypted using AES-256-GCM with a per-build PBKDF2-HMAC-SHA256 derived key and 96-bit nonce.
2. **Link via `objcopy`**: The encrypted payload is embedded directly into an object file using `ld -b binary` (`_binary_payload_enc_start`), keeping source code free of plaintext arrays.
3. **In-Memory Loader Stub**: The loader stub (`stub/loader.c`) decrypts payload bytes at runtime into anonymous memory (`mmap` + `mprotect`), executing segment loading without writing decrypted ELF files to disk.
4. **Anti-Analysis Threads**: Spawns background threads periodically monitoring `/proc/self/status` `TracerPid`, `ptrace(PTRACE_TRACEME)`, timing delays, open debugger ports, Frida artifacts (`frida-agent`), and maps anomalies.
5. **Self-Integrity Check**: Computes a SHA-256 checksum over the loader stub's executable `.text` segment to detect runtime patching or inline hooks.

---

## Repository Structure

```
.
├── protect.py          # Main CLI entry point
├── modules/
│   ├── __init__.py
│   ├── packer.py        # Compression & AES-256-GCM encryption
│   ├── keygen.py         # PBKDF2 key derivation & HWID binding
│   ├── stub_builder.py   # String-encryption pass & NDK Clang compilation
│   └── integrity.py      # .text section SHA-256 self-checksum verification
├── stub/
│   ├── loader.c         # Dynamic in-memory payload loader stub
│   ├── anti_debug.c     # TracerPid, ptrace, timing, and port scanners
│   ├── anti_debug.h
│   ├── anti_hook.c      # Frida, Xposed, and maps anomaly checks
│   ├── anti_hook.h
│   ├── string_crypt.h   # Compile-time string obfuscation macros
│   └── CMakeLists.txt   # CMake build configuration for stub
├── config.yaml          # Default build configuration parameters
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
Pack, encrypt, and compile the loader stub:
```bash
python protect.py build input_lib.so --output protected_lib.so --level 3
```

**Options**:
- `--output`, `-o`: Specify output `.so` filename.
- `--ndk-path`: Path to NDK toolchain root directory.
- `--level`, `-l`: Protection level:
  - `1`: Compression + AES-256-GCM encryption only
  - `2`: Level 1 + Anti-debugging background threads
  - `3`: Level 2 + Anti-hooking (Frida/Xposed detection) + `.text` self-integrity check
- `--bind-hwid`: Bind stub decryption key to target HWID string.

### 3. Verify Protected Binary (`verify`)
Perform a sanity check on the output binary:
```bash
python protect.py verify protected_lib.so
```

---

## Limitations

This protection suite significantly increases the time, effort, and technical skill required for casual reverse engineering by stripping debug symbols, encrypting native payloads, and obfuscating strings.

However, **it is not unbreakable**:
- Experienced reverse engineers equipped with custom Android kernels, eBPF dynamic memory inspection, hardware breakpoints, or advanced decompilers (IDA Pro / Ghidra) can dump memory regions after payload decryption occurs in RAM.

---

## License

MIT License
