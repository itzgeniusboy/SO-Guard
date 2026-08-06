"""
modules/packer.py
Compresses and encrypts target .so binary using AES-256-GCM.
Output payload layout: [12-byte Nonce] [Ciphertext] [16-byte Tag]
"""

import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def pack_so(input_path: str, key: bytes, nonce: bytes, algorithm: str = "zstd", level: int = 19) -> str:
    """
    Compresses target .so file and encrypts using AES-256-GCM.
    Returns path to temporary encrypted blob file.
    """
    with open(input_path, "rb") as f:
        data = f.read()

    # Compression pass
    if algorithm == "zstd":
        try:
            import zstandard as zstd
            cctx = zstd.ZstdCompressor(level=level)
            compressed_data = cctx.compress(data)
        except ImportError:
            import zlib
            compressed_data = zlib.compress(data, 9)
    else:
        import zlib
        compressed_data = zlib.compress(data, 9)

    # AES-256-GCM Encryption
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + 16-byte tag
    ct_and_tag = aesgcm.encrypt(nonce, compressed_data, None)

    # Payload format: [Nonce (12 bytes)] [Ciphertext + Tag]
    encrypted_blob = nonce + ct_and_tag

    build_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "build_tmp")
    os.makedirs(build_dir, exist_ok=True)
    out_blob_path = os.path.join(build_dir, "payload_enc.bin")

    with open(out_blob_path, "wb") as f:
        f.write(encrypted_blob)

    return out_blob_path
