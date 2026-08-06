#ifndef PBKDF2_H
#define PBKDF2_H

#include <stddef.h>
#include <stdint.h>

/**
 * Derives a key using PBKDF2 with HMAC-SHA256.
 * Equivalent to Python's hashlib.pbkdf2_hmac('sha256', passphrase, salt, iterations, dklen).
 *
 * @param passphrase Input passphrase buffer
 * @param passphrase_len Length of passphrase
 * @param salt Input salt buffer
 * @param salt_len Length of salt
 * @param iterations Number of PBKDF2 iterations (e.g. 100000)
 * @param out Output buffer for derived key
 * @param out_len Desired derived key length (dklen, e.g. 32)
 */
void pbkdf2_hmac_sha256(
    const uint8_t *passphrase,
    size_t passphrase_len,
    const uint8_t *salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t *out,
    size_t out_len
);

#endif // PBKDF2_H
