"""
modules/packer.py
Handles compression and AES-256-GCM encryption of target .so binaries.
"""

import os
import zlib
import lzma
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def pack_so(input_so_path: str, key: bytes, nonce: bytes, algorithm: str = "zstd", level: int = 19) -> str:
    """
    Reads target .so binary, compresses it, and encrypts it using AES-256-GCM.
    Returns path to the binary payload file payload.enc.
    """
    if not os.path.exists(input_so_path):
        raise FileNotFoundError(f"Input binary not found: {input_so_path}")

    with open(input_so_path, "rb") as f:
        raw_data = f.read()

    # 1. Compression step
    if algorithm.lower() == "zstd":
        try:
            import zstandard as zstd
            cctx = zstd.ZstdCompressor(level=level)
            compressed_data = cctx.compress(raw_data)
        except ImportError:
            # Fallback to zlib/deflate if zstandard python module isn't installed
            compressed_data = zlib.compress(raw_data, level=9)
    elif algorithm.lower() == "lzma":
        compressed_data = lzma.compress(raw_data, preset=9)
    else:
        # Default fallback
        compressed_data = zlib.compress(raw_data, level=9)

    # 2. Encryption step (AES-256-GCM)
    aesgcm = AESGCM(key)
    # Ciphertext contains appended 16-byte GCM tag
    ciphertext = aesgcm.encrypt(nonce, compressed_data, associated_data=None)

    # Store blob format: [96-bit Nonce (12 bytes)] + [Ciphertext + 16-byte Tag]
    enc_payload = nonce + ciphertext

    # Output payload.enc in temporary build location or current working dir
    output_dir = os.path.dirname(os.path.abspath(input_so_path))
    enc_blob_path = os.path.join(output_dir, "payload.enc")
    
    with open(enc_blob_path, "wb") as f:
        f.write(enc_payload)

    return enc_blob_path
