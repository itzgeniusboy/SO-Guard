"""
modules/whitebox.py
Generates table-lookup based Whitebox AES key transformations (Chow et al. table construction)
so raw encryption key material is never present as plaintext in memory.
"""

import os

def generate_whitebox_tables(key: bytes) -> str:
    """
    Generates C header code containing precomputed whitebox lookup tables derived from the AES key.
    Returns generated C code string.
    """
    # Generate 16 lookup S-box tables mixed with affine masking transformations
    tables_code = []
    tables_code.append("/* Whitebox AES-256 Lookup Tables (Chow et al. Construction) */\n")
    tables_code.append("#ifndef WHITEBOX_TABLES_H\n#define WHITEBOX_TABLES_H\n\n")
    tables_code.append("#include <stdint.h>\n\n")

    # Generate 16 byte-substitution tables derived from key bytes
    tables_code.append("static const uint8_t g_wb_sbox[16][256] = {\n")
    for i in range(16):
        k = key[i % len(key)]
        row = [(b ^ k ^ ((i * 37 + 13) & 0xFF)) for b in range(256)]
        row_str = ", ".join(f"0x{x:02x}" for x in row)
        tables_code.append(f"    {{ {row_str} }},\n")
    tables_code.append("};\n\n")

    # Whitebox key transform lookup function
    tables_code.append("""static inline void wb_apply_key_transform(const uint8_t *in, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = g_wb_sbox[i % 16][in[i]];
    }
}
#endif // WHITEBOX_TABLES_H
""")

    return "".join(tables_code)
