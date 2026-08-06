/*
 * Minimal embeddable AES-256-GCM implementation for loader stub.
 * Implements AES-256 block encryption and GHASH for Galois/Counter Mode (GCM).
 */

#include "aes_gcm.h"
#include <string.h>

/* --- AES-256 Core Implementation --- */

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint32_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

static void aes256_key_expansion(const uint8_t *key, uint8_t *round_keys) {
    memcpy(round_keys, key, 32);
    for (int i = 8; i < 60; i++) {
        uint8_t temp[4];
        memcpy(temp, &round_keys[(i - 1) * 4], 4);
        if (i % 8 == 0) {
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon[i / 8];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        } else if (i % 8 == 4) {
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }
        for (int j = 0; j < 4; j++) {
            round_keys[i * 4 + j] = round_keys[(i - 8) * 4 + j] ^ temp[j];
        }
    }
}

static void aes256_encrypt_block(const uint8_t *round_keys, const uint8_t *in, uint8_t *out) {
    uint8_t state[4][4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = in[i * 4 + j] ^ round_keys[i * 4 + j];
        }
    }

    for (int round = 1; round <= 14; round++) {
        // SubBytes & ShiftRows
        uint8_t temp[4][4];
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                temp[r][c] = sbox[state[r][(c + r) % 4]];
            }
        }
        // MixColumns (rounds 1-13)
        if (round < 14) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = temp[0][c], a1 = temp[1][c], a2 = temp[2][c], a3 = temp[3][c];
                state[0][c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
                state[1][c] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
                state[2][c] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
                state[3][c] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
            }
        } else {
            memcpy(state, temp, 16);
        }
        // AddRoundKey
        const uint8_t *rk = &round_keys[round * 16];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] ^= rk[i * 4 + j];
            }
        }
    }

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            out[i * 4 + j] = state[j][i];
        }
    }
}

/* --- GHASH & GCM Core Implementation --- */

static void ghash_multiply(uint8_t *x, const uint8_t *h) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, h, 16);

    for (int i = 0; i < 128; i++) {
        if ((x[i / 8] >> (7 - (i % 8))) & 1) {
            for (int j = 0; j < 16; j++) z[j] ^= v[j];
        }
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; j--) {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;
        if (lsb) {
            v[0] ^= 0xe1; // GCM polynomial
        }
    }
    memcpy(x, z, 16);
}

int aes_gcm_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag,
    size_t tag_len,
    uint8_t *plaintext
) {
    if (nonce_len != 12 || tag_len != 16) return -1;

    uint8_t round_keys[240];
    aes256_key_expansion(key, round_keys);

    uint8_t h[16] = {0};
    aes256_encrypt_block(round_keys, h, h);

    // Initial counter block J0
    uint8_t cb[16] = {0};
    memcpy(cb, nonce, 12);
    cb[15] = 1;

    uint8_t tag_mask[16];
    aes256_encrypt_block(round_keys, cb, tag_mask);

    // Decrypt ciphertext using CTR mode
    uint8_t ghash[16] = {0};
    size_t blocks = (ciphertext_len + 15) / 16;

    for (size_t i = 0; i < blocks; i++) {
        // Increment counter
        for (int j = 15; j >= 12; j--) {
            if (++cb[j] != 0) break;
        }

        uint8_t ctr_cipher[16];
        aes256_encrypt_block(round_keys, cb, ctr_cipher);

        size_t block_len = (i == blocks - 1 && ciphertext_len % 16 != 0) ? (ciphertext_len % 16) : 16;

        // GHASH over ciphertext
        uint8_t block[16] = {0};
        memcpy(block, ciphertext + i * 16, block_len);

        for (size_t j = 0; j < 16; j++) ghash[j] ^= block[j];
        ghash_multiply(ghash, h);

        for (size_t j = 0; j < block_len; j++) {
            plaintext[i * 16 + j] = ciphertext[i * 16 + j] ^ ctr_cipher[j];
        }
    }

    // Add length block to GHASH (0 bits AAD, ciphertext_len * 8 bits C)
    uint8_t len_block[16] = {0};
    uint64_t bit_len = (uint64_t)ciphertext_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[15 - i] = (uint8_t)(bit_len >> (i * 8));
    }

    for (size_t j = 0; j < 16; j++) ghash[j] ^= len_block[j];
    ghash_multiply(ghash, h);

    // Final auth tag calculation
    for (size_t j = 0; j < 16; j++) ghash[j] ^= tag_mask[j];

    // Constant-time tag check
    int diff = 0;
    for (size_t j = 0; j < 16; j++) {
        diff |= (ghash[j] ^ tag[j]);
    }

    return (diff == 0) ? 0 : -1;
}
