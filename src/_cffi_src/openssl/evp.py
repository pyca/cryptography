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
typedef ... EVP_MD_CTX;

typedef ... EVP_PKEY;
typedef ... EVP_PKEY_CTX;
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
int EVP_PKEY_size(EVP_PKEY *);
RSA *EVP_PKEY_get1_RSA(EVP_PKEY *);

int EVP_SignInit(EVP_MD_CTX *, const EVP_MD *);
int EVP_SignUpdate(EVP_MD_CTX *, const void *, size_t);
int EVP_SignFinal(EVP_MD_CTX *, unsigned char *, unsigned int *, EVP_PKEY *);

int EVP_VerifyInit(EVP_MD_CTX *, const EVP_MD *);
int EVP_VerifyUpdate(EVP_MD_CTX *, const void *, size_t);
int EVP_VerifyFinal(EVP_MD_CTX *, const unsigned char *, unsigned int,
                    EVP_PKEY *);


int EVP_PKEY_set1_RSA(EVP_PKEY *, RSA *);
int EVP_PKEY_set1_DSA(EVP_PKEY *, DSA *);

int EVP_PKEY_id(const EVP_PKEY *);

EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *);

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
