# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/ecdh.h>
"""

TYPES = """
"""

FUNCTIONS = """
int ECDH_compute_key(void *, size_t, const EC_POINT *, EC_KEY *,
                     void *(*)(const void *, size_t, void *, size_t *));
long SSL_CTX_set_ecdh_auto(SSL_CTX *, int);
"""

CUSTOMIZATIONS = """
#if (OPENSSL_API_COMPAT >= 0x10100000L) && !CRYPTOGRAPHY_IS_LIBRESSL
#define SSL_CTX_set_ecdh_auto(a, b) ((b) != 0)
#endif
"""
