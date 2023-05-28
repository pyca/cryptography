# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/pkcs7.h>
"""

TYPES = """
static const long Cryptography_HAS_PKCS7_FUNCS;

typedef struct {
    Cryptography_STACK_OF_X509 *cert;
    Cryptography_STACK_OF_X509_CRL *crl;
    ...;
} PKCS7_SIGNED;

typedef struct {
    Cryptography_STACK_OF_X509 *cert;
    Cryptography_STACK_OF_X509_CRL *crl;
    ...;
} PKCS7_SIGN_ENVELOPE;

typedef ... PKCS7_DIGEST;
typedef ... PKCS7_ENCRYPT;
typedef ... PKCS7_ENVELOPE;
typedef ... PKCS7_SIGNER_INFO;

typedef struct {
    ASN1_OBJECT *type;
    union {
        char *ptr;
        ASN1_OCTET_STRING *data;
        PKCS7_SIGNED *sign;
        PKCS7_ENVELOPE *enveloped;
        PKCS7_SIGN_ENVELOPE *signed_and_enveloped;
        PKCS7_DIGEST *digest;
        PKCS7_ENCRYPT *encrypted;
        ASN1_TYPE *other;
     } d;
    ...;
} PKCS7;

static const int PKCS7_TEXT;
"""

FUNCTIONS = """
void PKCS7_free(PKCS7 *);
int SMIME_write_PKCS7(BIO *, PKCS7 *, BIO *, int);
int PEM_write_bio_PKCS7_stream(BIO *, PKCS7 *, BIO *, int);
PKCS7_SIGNER_INFO *PKCS7_sign_add_signer(PKCS7 *, X509 *, EVP_PKEY *,
                                         const EVP_MD *, int);
int PKCS7_final(PKCS7 *, BIO *, int);
/* Included verify due to external consumer, see
   https://github.com/pyca/cryptography/issues/5433 */
int PKCS7_verify(PKCS7 *, Cryptography_STACK_OF_X509 *, X509_STORE *, BIO *,
                 BIO *, int);
PKCS7 *SMIME_read_PKCS7(BIO *, BIO **);
/* Included due to external consumer, see
   https://github.com/pyca/pyopenssl/issues/1031 */
Cryptography_STACK_OF_X509 *PKCS7_get0_signers(PKCS7 *,
                                               Cryptography_STACK_OF_X509 *,
                                               int);

int PKCS7_type_is_signed(PKCS7 *);
int PKCS7_type_is_enveloped(PKCS7 *);
int PKCS7_type_is_signedAndEnveloped(PKCS7 *);
int PKCS7_type_is_data(PKCS7 *);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_PKCS7_FUNCS = 0;

int (*SMIME_write_PKCS7)(BIO *, PKCS7 *, BIO *, int) = NULL;
int (*PEM_write_bio_PKCS7_stream)(BIO *, PKCS7 *, BIO *, int) = NULL;
PKCS7_SIGNER_INFO *(*PKCS7_sign_add_signer)(PKCS7 *, X509 *, EVP_PKEY *,
                                            const EVP_MD *, int) = NULL;
int (*PKCS7_final)(PKCS7 *, BIO *, int);
int (*PKCS7_verify)(PKCS7 *, Cryptography_STACK_OF_X509 *, X509_STORE *, BIO *,
                    BIO *, int) = NULL;
PKCS7 *(*SMIME_read_PKCS7)(BIO *, BIO **) = NULL;
Cryptography_STACK_OF_X509 *(*PKCS7_get0_signers)(PKCS7 *,
                                                  Cryptography_STACK_OF_X509 *,
                                                  int) = NULL;
#else
static const long Cryptography_HAS_PKCS7_FUNCS = 1;
#endif
"""
