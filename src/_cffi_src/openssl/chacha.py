# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#if CRYPTOGRAPHY_IS_LIBRESSL
#include <openssl/chacha.h>
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
#if CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_CHACHA20_API = 1;
#else
static const long Cryptography_HAS_CHACHA20_API = 0;
#endif

#if CRYPTOGRAPHY_IS_LIBRESSL
void Cryptography_CRYPTO_chacha_20(uint8_t *out, const uint8_t *in,
                                   size_t in_len, const uint8_t key[32],
                                   const uint8_t nonce[8], uint64_t counter) {
    CRYPTO_chacha_20(out, in, in_len, key, nonce, counter);
}
#else
void (*Cryptography_CRYPTO_chacha_20)(uint8_t *, const uint8_t *, size_t,
                                      const uint8_t[32], const uint8_t[8],
                                      uint64_t) = NULL;
#endif
"""
