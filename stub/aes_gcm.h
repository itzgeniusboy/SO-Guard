#ifndef AES_GCM_H
#define AES_GCM_H

#include <stddef.h>
#include <stdint.h>

/**
 * Perform AES-256-GCM decryption with tag verification.
 * 
 * @param key 32-byte (256-bit) AES key
 * @param nonce 12-byte GCM nonce/IV
 * @param nonce_len Length of nonce (must be 12)
 * @param ciphertext Input ciphertext bytes
 * @param ciphertext_len Length of ciphertext
 * @param tag 16-byte expected GCM authentication tag
 * @param tag_len Length of tag (must be 16)
 * @param plaintext Output buffer (must be at least ciphertext_len bytes)
 * 
 * @return 0 on success with valid tag, -1 on tag mismatch or error.
 */
int aes_gcm_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag,
    size_t tag_len,
    uint8_t *plaintext
);

#endif // AES_GCM_H
