#ifndef STRING_CRYPT_H
#define STRING_CRYPT_H

#include <stddef.h>

/*
 * Fallback compile-time string macro.
 * During stub_builder string_crypt pass, instances of ENC_STR("...") 
 * are replaced with inline stack-allocated XOR array decryption constructs.
 */
#ifndef ENC_STR
#define ENC_STR(str) (str)
#endif

#endif // STRING_CRYPT_H
