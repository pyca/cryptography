# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/evp.h>
"""

TYPES = """
typedef ... EVP_CIPHER;
typedef ... EVP_MD;

typedef ... EVP_PKEY;
static const int EVP_PKEY_RSA;
static const int EVP_PKEY_DSA;
static const int EVP_PKEY_DH;
static const int EVP_PKEY_EC;
static const int EVP_MAX_MD_SIZE;

static const int Cryptography_HAS_EVP_PKEY_DHX;
"""

FUNCTIONS = """
const EVP_CIPHER *EVP_get_cipherbyname(const char *);

const EVP_MD *EVP_get_digestbyname(const char *);

EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *);
int EVP_PKEY_type(int);
RSA *EVP_PKEY_get1_RSA(EVP_PKEY *);

int EVP_PKEY_set1_DSA(EVP_PKEY *, DSA *);

int EVP_PKEY_id(const EVP_PKEY *);

int EVP_PKEY_bits(const EVP_PKEY *);

int EVP_PKEY_assign_RSA(EVP_PKEY *, RSA *);
"""

CUSTOMIZATIONS = """
#ifdef EVP_PKEY_DHX
const long Cryptography_HAS_EVP_PKEY_DHX = 1;
#else
const long Cryptography_HAS_EVP_PKEY_DHX = 0;
#endif
"""
