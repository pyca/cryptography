# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif
"""

TYPES = """
static const int Cryptography_HAS_ECDH;
static const int Cryptography_HAS_ECDH_SET_CURVE;
"""

FUNCTIONS = """
"""

MACROS = """
int ECDH_compute_key(void *, size_t, const EC_POINT *, EC_KEY *,
                     void *(*)(const void *, size_t, void *, size_t *));
int SSL_CTX_set_ecdh_auto(SSL_CTX *ctx, int onoff);
"""

CUSTOMIZATIONS = """
#ifdef OPENSSL_NO_ECDH
static const long Cryptography_HAS_ECDH = 0;

int (*ECDH_compute_key)(void *, size_t, const EC_POINT *, EC_KEY *,
                        void *(*)(const void *, size_t, void *,
                        size_t *)) = NULL;

#else
static const long Cryptography_HAS_ECDH = 1;
#endif
#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_102 || defined(LIBRESSL_VERSION_NUMBER)
static const long Cryptography_HAS_ECDH_SET_CURVE = 0;
#else
static const long Cryptography_HAS_ECDH_SET_CURVE = 1;
#endif
"""
