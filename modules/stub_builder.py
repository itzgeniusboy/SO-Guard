"""
modules/stub_builder.py
Handles string encryption preprocessing pass and compilation of the C loader stub via NDK Clang.
"""

import os
import subprocess
import shutil
import re

def encrypt_string_pass(c_source_code: str, key_byte: int = 0x5A) -> str:
    """
    Scans C source code for ENC_STR("plaintext") macros and replaces them with inline XOR decryptor constructs.
    """
    def replace_match(match):
        raw_str = match.group(1)
        str_bytes = raw_str.encode('utf-8') + b'\x00'
        enc_bytes = [b ^ key_byte for b in str_bytes]
        array_init = ", ".join(f"0x{b:02x}" for b in enc_bytes)
        
        return (
            f"(__extension__ ({{ static const unsigned char _enc[] = {{{array_init}}}; "
            f"static char _dec[{len(str_bytes)}]; "
            f"for(size_t _i = 0; _i < {len(str_bytes)}; _i++) {{ _dec[_i] = _enc[_i] ^ 0x{key_byte:02x}; }} "
            f"_dec; }}))"
        )

    return re.sub(r'ENC_STR\("([^"]*)"\)', replace_match, c_source_code)

def find_ndk_clang(ndk_path=None):
    """Locates the aarch64 Android NDK clang compiler binary."""
    if ndk_path and os.path.exists(ndk_path):
        clang_path = os.path.join(ndk_path, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin", "aarch64-linux-android21-clang")
        if os.path.exists(clang_path):
            return clang_path

    env_ndk = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("NDK_PATH")
    if env_ndk and os.path.exists(env_ndk):
        clang_path = os.path.join(env_ndk, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin", "aarch64-linux-android21-clang")
        if os.path.exists(clang_path):
            return clang_path

    which_clang = shutil.which("aarch64-linux-android21-clang") or shutil.which("clang")
    return which_clang

def build_stub(enc_blob_path: str, keys_info: dict, protection_level: int, output_path: str, ndk_path: str = None, min_api: int = 21, ollvm_path: str = None, enable_whitebox: bool = False) -> str:
    """
    Preprocesses C loader files, compiles via NDK clang / OLLVM clang, embeds binary payload, and strips output.
    Raises RuntimeError on subprocess build failures.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    stub_dir = os.path.join(base_dir, "stub")
    build_dir = os.path.join(base_dir, "build_tmp")
    os.makedirs(build_dir, exist_ok=True)

    # 1. Preprocess string encryption in C files
    c_files = ["loader.c", "aes_gcm.c", "zstddeclib.c", "elf_loader.c", "anti_debug.c", "anti_hook.c", "anti_env.c", "pbkdf2.c"]
    processed_files = []

    # Write build_params.h with build-specific salt, iterations, and passphrase
    salt_bytes = keys_info.get("salt", b"\x00" * 16)
    salt_array = ", ".join(f"0x{b:02x}" for b in salt_bytes)
    passphrase_bytes = keys_info.get("passphrase", b"\x00" * 32)
    passphrase_array = ", ".join(f"0x{b:02x}" for b in passphrase_bytes)
    iterations = keys_info.get("iterations", 100000)

    build_params_h = os.path.join(build_dir, "build_params.h")
    with open(build_params_h, "w", encoding="utf-8") as f:
        f.write("#ifndef BUILD_PARAMS_H\n#define BUILD_PARAMS_H\n\n")
        f.write(f"static const unsigned char BUILD_SALT[] = {{{salt_array}}};\n")
        f.write(f"static const size_t BUILD_SALT_LEN = {len(salt_bytes)};\n")
        f.write(f"static const unsigned char BUILD_PASSPHRASE[] = {{{passphrase_array}}};\n")
        f.write(f"static const size_t BUILD_PASSPHRASE_LEN = {len(passphrase_bytes)};\n")
        f.write(f"static const unsigned int BUILD_ITERATIONS = {iterations};\n\n")
        f.write("#endif // BUILD_PARAMS_H\n")

    for filename in c_files:
        src_file = os.path.join(stub_dir, filename)
        if not os.path.exists(src_file):
            continue

        with open(src_file, "r", encoding="utf-8") as f:
            code = f.read()

        encrypted_code = encrypt_string_pass(code, key_byte=keys_info["salt"][0] if keys_info.get("salt") else 0x7E)

        dst_file = os.path.join(build_dir, filename)
        with open(dst_file, "w", encoding="utf-8") as f:
            f.write(encrypted_code)

        processed_files.append(dst_file)

    # 2. Prepare payload object file via objcopy / ld -b binary
    objcopy_tool = shutil.which("aarch64-linux-android-objcopy") or shutil.which("llvm-objcopy") or "objcopy"
    payload_obj = os.path.join(build_dir, "payload.o")

    cmd_objcopy = [
        objcopy_tool,
        "-I", "binary",
        "-O", "elf64-littleaarch64",
        "-B", "aarch64",
        enc_blob_path,
        payload_obj
    ]
    
    res_objcopy = subprocess.run(cmd_objcopy, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res_objcopy.returncode != 0:
        raise RuntimeError(f"objcopy failed:\n{res_objcopy.stderr.decode('utf-8', errors='replace')}")

    # 3. Compiler selection (OLLVM vs NDK Clang)
    if ollvm_path and os.path.exists(ollvm_path):
        clang_path = ollvm_path
        use_ollvm_flags = True
    else:
        clang_path = find_ndk_clang(ndk_path) or "clang"
        use_ollvm_flags = False
        if ollvm_path:
            print(f"[WARNING] OLLVM binary path '{ollvm_path}' not found. Falling back to vanilla NDK clang with -O2.")

    compile_cmd = [
        clang_path,
        "-fPIC",
        "-shared",
        f"-DPROTECTION_LEVEL={protection_level}",
        f"-I{stub_dir}",
        f"-I{build_dir}",
        "-O2",
        "-Wall",
        "-o", output_path
    ]

    # Apply OLLVM flags to protection files if OLLVM compiler available
    if use_ollvm_flags:
        compile_cmd.extend([
            "-mllvm", "-fla",
            "-mllvm", "-sub",
            "-mllvm", "-bcf",
            "-mllvm", "-bcf_prob=70"
        ])

    compile_cmd.extend(processed_files)
    compile_cmd.append(payload_obj)

    res_compile = subprocess.run(compile_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res_compile.returncode != 0:
        if os.path.exists(output_path):
            os.remove(output_path)
        raise RuntimeError(f"Clang compilation failed:\n{res_compile.stderr.decode('utf-8', errors='replace')}")

    # 4. Strip symbols
    strip_tool = shutil.which("llvm-strip") or shutil.which("strip")
    if strip_tool and os.path.exists(output_path):
        subprocess.run([strip_tool, "--strip-all", output_path], stderr=subprocess.DEVNULL)

    return output_path
