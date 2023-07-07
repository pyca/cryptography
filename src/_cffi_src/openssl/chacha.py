# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#if CRYPTOGRAPHY_IS_BORINGSSL
#include <openssl/chacha.h>
#include <stdint.h>
#endif"""

TYPES = """
static const long Cryptography_HAS_CHACHA20_API;
"""

FUNCTIONS = """
/* Signature is different between LibreSSL and BoringSSL, so expose via
   different symbol name */
void Cryptography_CRYPTO_chacha_20(uint8_t *, const uint8_t *, size_t,
                                   const uint8_t[32], const uint8_t[8],
                                   uint64_t);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_CHACHA20_API = 1;
#else
static const long Cryptography_HAS_CHACHA20_API = 0;
#endif

#if CRYPTOGRAPHY_IS_BORINGSSL
void Cryptography_CRYPTO_chacha_20(uint8_t *out, const uint8_t *in,
                                   size_t in_len, const uint8_t key[32],
                                   const uint8_t nonce[8], uint64_t counter) {
    /* BoringSSL uses a 32 bit counter, leaving the other 32 bits as part of
       the nonce. Here we adapt the 64 bit counter so that the first 32 bits
       are used as a counter and the other 32 bits as the beginning of the
       nonce */
    uint32_t new_counter = (uint32_t) counter;
    uint8_t new_nonce[12];
    memcpy(new_nonce, ((uint8_t*) &counter) + 4, 4);
    memcpy(new_nonce + 4, nonce, 8);

    /* The maximum amount of bytes that can be encrypted using a 32-bit
       counter */
    uint64_t max_bytes = ((uint64_t) UINT32_MAX + 1) * 64;

    /* Since BoringSSL uses a smaller 32 bit counter, it behaves differently
       from OpenSSL/LibreSSL during counter overflow. In order to have
       consistent implementations, we split the input so that no call to the
       API results in counter overflow, and we manually increase the counter
       as if it was 64 bits. */
    uint64_t bytes_before_overflow = max_bytes - (uint64_t) new_counter * 64;
    uint64_t bytes_remaining = in_len;
    uint64_t bytes_processed = 0;
    while (bytes_remaining > 0) {
        uint64_t next_batch = bytes_remaining < bytes_before_overflow ?
                              bytes_remaining : bytes_before_overflow;
        CRYPTO_chacha_20(out + bytes_processed, in + bytes_processed,
                         next_batch, key, new_nonce, new_counter);
        bytes_before_overflow = max_bytes;
        bytes_remaining -= next_batch;
        bytes_processed += next_batch;
        /* Since each batch (except the last one) saturates the 32 bit
           counter, we increase it by treating it and the first 32 bits
           of the nonce as a 64 bit counter, matching Libre and OpenSSL */
        new_counter = 0;
        uint32_t* nonce_counter = (uint32_t*) new_nonce;
        (*nonce_counter)++;
    }
}
#else
void (*Cryptography_CRYPTO_chacha_20)(uint8_t *, const uint8_t *, size_t,
                                      const uint8_t[32], const uint8_t[8],
                                      uint64_t) = NULL;
#endif
"""
