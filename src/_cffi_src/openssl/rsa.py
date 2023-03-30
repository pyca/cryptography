# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/rsa.h>
"""

TYPES = """
typedef ... RSA;
typedef ... BN_GENCB;
static const int RSA_PKCS1_PADDING;
static const int RSA_PKCS1_OAEP_PADDING;
static const int RSA_PKCS1_PSS_PADDING;
static const int RSA_F4;
static const int RSA_PSS_SALTLEN_AUTO;

static const int Cryptography_HAS_IMPLICIT_RSA_REJECTION;
"""

FUNCTIONS = """
RSA *RSA_new(void);
void RSA_free(RSA *);
int RSA_generate_key_ex(RSA *, int, BIGNUM *, BN_GENCB *);
int RSA_check_key(const RSA *);
RSA *RSAPublicKey_dup(RSA *);
int RSA_blinding_on(RSA *, BN_CTX *);
int RSA_print(BIO *, const RSA *, int);

int RSA_set0_key(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
int RSA_set0_factors(RSA *, BIGNUM *, BIGNUM *);
int RSA_set0_crt_params(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
void RSA_get0_key(const RSA *, const BIGNUM **, const BIGNUM **,
                  const BIGNUM **);
void RSA_get0_factors(const RSA *, const BIGNUM **, const BIGNUM **);
void RSA_get0_crt_params(const RSA *, const BIGNUM **, const BIGNUM **,
                         const BIGNUM **);
int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *, int);
int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *, int);
int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *, EVP_MD *);
int EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX *, unsigned char *, int);

int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *, EVP_MD *);
"""

CUSTOMIZATIONS = """
// BoringSSL doesn't define this constant, but the value is used for
// automatic salt length computation as in OpenSSL and LibreSSL
#if !defined(RSA_PSS_SALTLEN_AUTO)
#define RSA_PSS_SALTLEN_AUTO -2
#endif

#if defined(EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION)
static const int Cryptography_HAS_IMPLICIT_RSA_REJECTION = 1;
#else
static const int Cryptography_HAS_IMPLICIT_RSA_REJECTION = 0;
#endif
"""
