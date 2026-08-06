"""
modules/keygen.py
Handles per-build PBKDF2-HMAC-SHA256 key derivation and optional HWID binding.
"""

import os
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def generate_build_keys(bind_hwid: str = None, storage_dir: str = "./keys") -> dict:
    """
    Generates build-specific 256-bit AES key, 96-bit nonce, and salt.
    """
    os.makedirs(storage_dir, exist_ok=True)

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    passphrase = secrets.token_bytes(32)

    if bind_hwid:
        passphrase = passphrase + bind_hwid.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(passphrase)

    key_file_path = os.path.join(storage_dir, f"build_{secrets.token_hex(4)}.key")
    with open(key_file_path, "wb") as f:
        f.write(key)

    return {
        "key": key,
        "nonce": nonce,
        "salt": salt,
        "passphrase": passphrase,
        "iterations": 100000,
        "key_file": key_file_path
    }
