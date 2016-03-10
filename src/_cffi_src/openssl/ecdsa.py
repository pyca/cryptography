# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#ifndef OPENSSL_NO_ECDSA
#include <openssl/ecdsa.h>
#endif
"""

TYPES = """
static const int Cryptography_HAS_ECDSA;

typedef ... ECDSA_SIG;

typedef ... CRYPTO_EX_new;
typedef ... CRYPTO_EX_dup;
typedef ... CRYPTO_EX_free;
"""

FUNCTIONS = """
"""

MACROS = """
ECDSA_SIG *ECDSA_SIG_new();
void ECDSA_SIG_free(ECDSA_SIG *);
int i2d_ECDSA_SIG(const ECDSA_SIG *, unsigned char **);
ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **s, const unsigned char **, long);
ECDSA_SIG *ECDSA_do_sign(const unsigned char *, int, EC_KEY *);
ECDSA_SIG *ECDSA_do_sign_ex(const unsigned char *, int, const BIGNUM *,
                            const BIGNUM *, EC_KEY *);
int ECDSA_do_verify(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *);
int ECDSA_sign_setup(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **);
int ECDSA_sign(int, const unsigned char *, int, unsigned char *,
               unsigned int *, EC_KEY *);
int ECDSA_sign_ex(int, const unsigned char *, int dgstlen, unsigned char *,
                  unsigned int *, const BIGNUM *, const BIGNUM *, EC_KEY *);
int ECDSA_verify(int, const unsigned char *, int, const unsigned char *, int,
                 EC_KEY *);
int ECDSA_size(const EC_KEY *);

"""

CUSTOMIZATIONS = """
#ifdef OPENSSL_NO_ECDSA
static const long Cryptography_HAS_ECDSA = 0;

typedef struct {
    BIGNUM *r;
    BIGNUM *s;
} ECDSA_SIG;

ECDSA_SIG* (*ECDSA_SIG_new)() = NULL;
void (*ECDSA_SIG_free)(ECDSA_SIG *) = NULL;
int (*i2d_ECDSA_SIG)(const ECDSA_SIG *, unsigned char **) = NULL;
ECDSA_SIG* (*d2i_ECDSA_SIG)(ECDSA_SIG **s, const unsigned char **,
                            long) = NULL;
ECDSA_SIG* (*ECDSA_do_sign)(const unsigned char *, int, EC_KEY *eckey) = NULL;
ECDSA_SIG* (*ECDSA_do_sign_ex)(const unsigned char *, int, const BIGNUM *,
                               const BIGNUM *, EC_KEY *) = NULL;
int (*ECDSA_do_verify)(const unsigned char *, int, const ECDSA_SIG *,
                       EC_KEY *) = NULL;
int (*ECDSA_sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **) = NULL;
int (*ECDSA_sign)(int, const unsigned char *, int, unsigned char *,
                  unsigned int *, EC_KEY *) = NULL;
int (*ECDSA_sign_ex)(int, const unsigned char *, int dgstlen, unsigned char *,
                     unsigned int *, const BIGNUM *, const BIGNUM *,
                     EC_KEY *) = NULL;
int (*ECDSA_verify)(int, const unsigned char *, int, const unsigned char *,
                    int, EC_KEY *) = NULL;
int (*ECDSA_size)(const EC_KEY *) = NULL;

#else
static const long Cryptography_HAS_ECDSA = 1;
#endif
"""
