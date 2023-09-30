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
static const int RSA_F4;

static const int Cryptography_HAS_IMPLICIT_RSA_REJECTION;
"""

FUNCTIONS = """
RSA *RSA_new(void);
void RSA_free(RSA *);
int RSA_generate_key_ex(RSA *, int, BIGNUM *, BN_GENCB *);
int RSA_check_key(const RSA *);
int RSA_print(BIO *, const RSA *, int);
"""

CUSTOMIZATIONS = """
#if defined(EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION)
static const int Cryptography_HAS_IMPLICIT_RSA_REJECTION = 1;
#else
static const int Cryptography_HAS_IMPLICIT_RSA_REJECTION = 0;
#endif
"""
