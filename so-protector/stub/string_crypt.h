#ifndef STRING_CRYPT_H
#define STRING_CRYPT_H

/* Compile-time string obfuscation macro marker.
 * modules/stub_builder.py preprocesses all ENC_STR("plaintext") calls into inline XOR decryptors.
 */
#define ENC_STR(s) (s)

#endif // STRING_CRYPT_H
