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

import os
import subprocess
import shutil
import re
import platform

def detect_host_platform() -> str:
    """
    Detects host platform: 'termux', 'windows', 'darwin', or 'linux'.
    """
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix or os.path.exists("/data/data/com.termux"):
        return "termux"
    
    sys_name = platform.system()
    if sys_name == "Windows":
        return "windows"
    elif sys_name == "Darwin":
        return "darwin"
    else:
        return "linux"

def find_ndk_root(ndk_path=None):
    """Locates the Android NDK root directory if available."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo_ndk = os.path.join(base_dir, "ndk")
    
    candidates = [
        ndk_path,
        os.environ.get("ANDROID_NDK_HOME"),
        os.environ.get("NDK_PATH"),
        repo_ndk if os.path.exists(repo_ndk) else None
    ]
    
    host_plat = detect_host_platform()
    if host_plat == "windows":
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        if local_appdata:
            ndk_sdk_dir = os.path.join(local_appdata, "Android", "Sdk", "ndk")
            if os.path.exists(ndk_sdk_dir):
                subdirs = [os.path.join(ndk_sdk_dir, d) for d in os.listdir(ndk_sdk_dir)]
                candidates.extend(sorted(subdirs, reverse=True))
    elif host_plat in ("linux", "darwin"):
        home = os.environ.get("HOME", "")
        if home:
            ndk_sdk_dir = os.path.join(home, "Android", "Sdk", "ndk")
            if os.path.exists(ndk_sdk_dir):
                subdirs = [os.path.join(ndk_sdk_dir, d) for d in os.listdir(ndk_sdk_dir)]
                candidates.extend(sorted(subdirs, reverse=True))

    for cand in candidates:
        if cand and os.path.exists(cand):
            # If cand contains nested directory from unzipping (e.g. android-ndk-r26b)
            if os.path.exists(os.path.join(cand, "toolchains")):
                return cand
            for sub in os.listdir(cand):
                full_sub = os.path.join(cand, sub)
                if os.path.isdir(full_sub) and os.path.exists(os.path.join(full_sub, "toolchains")):
                    return full_sub
    return None

def find_ndk_clang(ndk_path=None, min_api=21):
    """
    Locates the aarch64 compiler binary.
    Returns tuple (mode, compiler_path) where mode is 'termux-native', 'ndk', or 'system'.
    """
    host_plat = detect_host_platform()
    
    # 1. Termux detection
    if host_plat == "termux":
        clang_bin = shutil.which("clang")
        if clang_bin:
            return ("termux-native", clang_bin)
        return ("termux-missing", None)

    # 2. Windows / Linux / Darwin NDK detection
    ndk_root = find_ndk_root(ndk_path)
    if ndk_root:
        arch_sub = "windows-x86_64" if host_plat == "windows" else ("darwin-x86_64" if host_plat == "darwin" else "linux-x86_64")
        ext = ".cmd" if host_plat == "windows" else ""
        
        # Check specific API target binary first
        target_clang = os.path.join(ndk_root, "toolchains", "llvm", "prebuilt", arch_sub, "bin", f"aarch64-linux-android{min_api}-clang{ext}")
        if os.path.exists(target_clang):
            return ("ndk", target_clang)
            
        # Check generic clang binary
        ext_bin = ".exe" if host_plat == "windows" else ""
        generic_clang = os.path.join(ndk_root, "toolchains", "llvm", "prebuilt", arch_sub, "bin", f"clang{ext_bin}")
        if os.path.exists(generic_clang):
            return ("ndk", generic_clang)

    # 3. Fallback to system clang
    which_clang = shutil.which(f"aarch64-linux-android{min_api}-clang") or shutil.which("clang")
    if which_clang:
        return ("system", which_clang)
        
    return ("none", None)

def find_ndk_tool(tool_name: str, ndk_path=None) -> str:
    """Finds binary tools such as llvm-objcopy or llvm-strip."""
    host_plat = detect_host_platform()
    ext = ".exe" if host_plat == "windows" else ""
    
    ndk_root = find_ndk_root(ndk_path)
    if ndk_root:
        arch_sub = "windows-x86_64" if host_plat == "windows" else ("darwin-x86_64" if host_plat == "darwin" else "linux-x86_64")
        tool_bin = os.path.join(ndk_root, "toolchains", "llvm", "prebuilt", arch_sub, "bin", f"{tool_name}{ext}")
        if os.path.exists(tool_bin):
            return tool_bin

    which_tool = (
        shutil.which(f"aarch64-linux-android-{tool_name}")
        or shutil.which(tool_name)
        or shutil.which(f"llvm-{tool_name}")
    )
    return which_tool or tool_name

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
