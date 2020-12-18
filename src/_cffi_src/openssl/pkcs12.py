# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/pkcs12.h>
"""

TYPES = """
typedef ... PKCS12;
typedef ... X509_SIG;

static const int PKCS12_DEFAULT_ITER;
"""

FUNCTIONS = """
void PKCS12_free(PKCS12 *);

PKCS12 *d2i_PKCS12_bio(BIO *, PKCS12 **);
int i2d_PKCS12_bio(BIO *, PKCS12 *);
int PKCS12_parse(PKCS12 *, const char *, EVP_PKEY **, X509 **,
                 Cryptography_STACK_OF_X509 **);
PKCS12 *PKCS12_create(char *, char *, EVP_PKEY *, X509 *,
                      Cryptography_STACK_OF_X509 *, int, int, int, int, int);

void X509_SIG_free(X509_SIG *);
X509_SIG *PKCS8_set0_pbe(const char *, int, PKCS8_PRIV_KEY_INFO *,
                         X509_ALGOR *);
/* LibreSSL does not have PKCS8_set0_pbe() */
X509_SIG *PKCS8_encrypt(int, const EVP_CIPHER *, const char *, int,
                        unsigned char *, int, int, PKCS8_PRIV_KEY_INFO *);
"""

CUSTOMIZATIONS = """
#if !CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_PKCS8_SET0_PBE = 1;
#else
static const long Cryptography_HAS_PKCS8_SET0_PBE = 0;
X509_SIG* (*PKCS8_set0_pbe)(const char *, int, PKCS8_PRIV_KEY_INFO *,
                            X509_ALGOR *) = NULL;
#endif
"""
