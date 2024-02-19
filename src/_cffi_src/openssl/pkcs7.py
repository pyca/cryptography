# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/pkcs7.h>
"""

TYPES = """
static const long Cryptography_HAS_PKCS7_FUNCS;
typedef ... PKCS7;
static const int PKCS7_TEXT;
"""

FUNCTIONS = """
void PKCS7_free(PKCS7 *);
/* Included verify due to external consumer, see
   https://github.com/pyca/cryptography/issues/5433 */
int PKCS7_verify(PKCS7 *, Cryptography_STACK_OF_X509 *, X509_STORE *, BIO *,
                 BIO *, int);
PKCS7 *SMIME_read_PKCS7(BIO *, BIO **);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_PKCS7_FUNCS = 0;

int (*PKCS7_verify)(PKCS7 *, Cryptography_STACK_OF_X509 *, X509_STORE *, BIO *,
                    BIO *, int) = NULL;
PKCS7 *(*SMIME_read_PKCS7)(BIO *, BIO **) = NULL;
#else
static const long Cryptography_HAS_PKCS7_FUNCS = 1;
#endif
"""
