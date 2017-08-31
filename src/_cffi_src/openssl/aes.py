# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/aes.h>
"""

TYPES = """
static const int Cryptography_HAS_AES_WRAP;

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

CUSTOMIZATIONS = """
static const long Cryptography_HAS_AES_WRAP = 1;
"""
