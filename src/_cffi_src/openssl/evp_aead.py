# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#if CRYPTOGRAPHY_IS_BORINGSSL
#include <openssl/aead.h>
#endif
"""

TYPES = """
typedef ... EVP_AEAD;
typedef ... EVP_AEAD_CTX;
static const size_t EVP_AEAD_DEFAULT_TAG_LENGTH;

static const long Cryptography_HAS_EVP_AEAD;
"""

FUNCTIONS = """
const EVP_AEAD *EVP_aead_chacha20_poly1305(void);
void EVP_AEAD_CTX_free(EVP_AEAD_CTX *);
int EVP_AEAD_CTX_seal(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t,
                      const uint8_t *, size_t, const uint8_t *, size_t,
                      const uint8_t *, size_t);
int EVP_AEAD_CTX_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t,
                      const uint8_t *, size_t, const uint8_t *, size_t,
                      const uint8_t *, size_t);
size_t EVP_AEAD_max_overhead(const EVP_AEAD *);
/* The function EVP_AEAD_CTX_NEW() has different signatures in BoringSSL and
   LibreSSL, so we cannot declare it here. We define a wrapper for it instead.
*/
EVP_AEAD_CTX *Cryptography_EVP_AEAD_CTX_new(const EVP_AEAD *,
                                            const uint8_t *, size_t,
                                            size_t);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_IS_BORINGSSL || CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_EVP_AEAD = 1;
#else
static const long Cryptography_HAS_EVP_AEAD = 0;
#endif

#if CRYPTOGRAPHY_IS_BORINGSSL
EVP_AEAD_CTX *Cryptography_EVP_AEAD_CTX_new(const EVP_AEAD *aead,
                                            const uint8_t *key,
                                            size_t key_len, size_t tag_len) {
   return EVP_AEAD_CTX_new(aead, key, key_len, tag_len);
}
#elif CRYPTOGRAPHY_IS_LIBRESSL
EVP_AEAD_CTX *Cryptography_EVP_AEAD_CTX_new(const EVP_AEAD *aead,
                                            const uint8_t *key,
                                            size_t key_len, size_t tag_len) {
   EVP_AEAD_CTX *ctx = EVP_AEAD_CTX_new();
   if (ctx == NULL) {
      return NULL;
   }

   /* This mimics BoringSSL's behavior: any error here is pushed onto
      the stack.
   */
   int result = EVP_AEAD_CTX_init(ctx, aead, key, key_len, tag_len, NULL);
   if (result != 1) {
      return NULL;
   }

   return ctx;
}
#else
typedef void EVP_AEAD;
typedef void EVP_AEAD_CTX;
static const size_t EVP_AEAD_DEFAULT_TAG_LENGTH = 0;
const EVP_AEAD *(*EVP_aead_chacha20_poly1305)(void) = NULL;
void (*EVP_AEAD_CTX_free)(EVP_AEAD_CTX *) = NULL;
int (*EVP_AEAD_CTX_seal)(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t,
                         const uint8_t *, size_t, const uint8_t *, size_t,
                         const uint8_t *, size_t) = NULL;
int (*EVP_AEAD_CTX_open)(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t,
                         const uint8_t *, size_t, const uint8_t *, size_t,
                         const uint8_t *, size_t) = NULL;
size_t (*EVP_AEAD_max_overhead)(const EVP_AEAD *) = NULL;
EVP_AEAD_CTX *(*Cryptography_EVP_AEAD_CTX_new)(const EVP_AEAD *,
                                               const uint8_t *, size_t,
                                               size_t) = NULL;
#endif
"""
