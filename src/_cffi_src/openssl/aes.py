# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/aes.h>
"""

TYPES = """
static const int Cryptography_HAS_AES_WRAP;
static const int Cryptography_HAS_AES_CTR128_ENCRYPT;

struct aes_key_st {
    ...;
};
typedef struct aes_key_st AES_KEY;
"""

FUNCTIONS = """
int AES_set_encrypt_key(const unsigned char *, const int, AES_KEY *);
int AES_set_decrypt_key(const unsigned char *, const int, AES_KEY *);

int AES_wrap_key(AES_KEY *, const unsigned char *, unsigned char *,
                 const unsigned char *, unsigned int);
int AES_unwrap_key(AES_KEY *, const unsigned char *, unsigned char *,
                   const unsigned char *, unsigned int);
"""

MACROS = """
/* The ctr128_encrypt function is only useful in 1.0.0. We can use EVP for
   this in 1.0.1+. */
void AES_ctr128_encrypt(const unsigned char *, unsigned char *,
                        size_t, const AES_KEY *, unsigned char[],
                        unsigned char[], unsigned int *);
"""

CUSTOMIZATIONS = """
static const long Cryptography_HAS_AES_WRAP = 1;
#if CRYPTOGRAPHY_OPENSSL_110_OR_GREATER && !defined(LIBRESSL_VERSION_NUMBER)
static const int Cryptography_HAS_AES_CTR128_ENCRYPT = 0;
void (*AES_ctr128_encrypt)(const unsigned char *, unsigned char *,
                           size_t, const AES_KEY *,
                           unsigned char[], unsigned char[],
                           unsigned int *) = NULL;
#else
static const int Cryptography_HAS_AES_CTR128_ENCRYPT = 1;
#endif
"""
