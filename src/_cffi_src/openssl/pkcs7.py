# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/pkcs7.h>
"""

TYPES = """
typedef struct {
    ASN1_OBJECT *type;
    ...;
} PKCS7;

static const int PKCS7_BINARY;
static const int PKCS7_DETACHED;
static const int PKCS7_NOATTR;
static const int PKCS7_NOCERTS;
static const int PKCS7_NOCHAIN;
static const int PKCS7_NOINTERN;
static const int PKCS7_NOSIGS;
static const int PKCS7_NOSMIMECAP;
static const int PKCS7_NOVERIFY;
static const int PKCS7_STREAM;
static const int PKCS7_TEXT;
"""

FUNCTIONS = """
PKCS7 *SMIME_read_PKCS7(BIO *, BIO **);
int SMIME_write_PKCS7(BIO *, PKCS7 *, BIO *, int);

void PKCS7_free(PKCS7 *);

PKCS7 *PKCS7_sign(X509 *, EVP_PKEY *, Cryptography_STACK_OF_X509 *,
                  BIO *, int);
int PKCS7_verify(PKCS7 *, Cryptography_STACK_OF_X509 *, X509_STORE *, BIO *,
                 BIO *, int);
Cryptography_STACK_OF_X509 *PKCS7_get0_signers(PKCS7 *,
                                               Cryptography_STACK_OF_X509 *,
                                               int);

PKCS7 *PKCS7_encrypt(Cryptography_STACK_OF_X509 *, BIO *,
                     const EVP_CIPHER *, int);
int PKCS7_decrypt(PKCS7 *, EVP_PKEY *, X509 *, BIO *, int);
"""

MACROS = """
int PKCS7_type_is_signed(PKCS7 *);
int PKCS7_type_is_enveloped(PKCS7 *);
int PKCS7_type_is_signedAndEnveloped(PKCS7 *);
int PKCS7_type_is_data(PKCS7 *);
"""

CUSTOMIZATIONS = ""
