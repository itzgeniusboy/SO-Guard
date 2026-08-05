"""
modules/keygen.py
Handles per-build cryptographic key derivation, HWID binding, and key storage.
"""

import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def generate_build_keys(bind_hwid: str = None, storage_dir: str = "./keys") -> dict:
    """
    Generates a 256-bit AES key derived via PBKDF2-HMAC-SHA256 from a random passphrase and salt.
    Optionally binds key to HWID string. Saves raw details to keys directory (gitignored).
    """
    os.makedirs(storage_dir, exist_ok=True)

    passphrase = os.urandom(32)
    salt = os.urandom(16)
    nonce = os.urandom(12) # 96-bit nonce for AES-GCM

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    derived_key = kdf.derive(passphrase)

    # Apply HWID binding if requested
    if bind_hwid:
        hwid_hash = hashlib.sha256(bind_hwid.encode('utf-8')).digest()
        # XOR key with HWID hash
        key_bytes = bytes(a ^ b for a, b in zip(derived_key, hwid_hash))
    else:
        key_bytes = derived_key

    # Save details securely in storage_dir
    key_file_path = os.path.join(storage_dir, "last_build_key.bin")
    with open(key_file_path, "wb") as f:
        f.write(key_bytes)

    return {
        "key": key_bytes,
        "passphrase": passphrase,
        "salt": salt,
        "nonce": nonce,
        "bind_hwid": bind_hwid,
        "key_file": key_file_path
    }
