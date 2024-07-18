# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/pem.h>
"""

TYPES = """
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
"""

FUNCTIONS = """
X509 *PEM_read_bio_X509(BIO *, X509 **, pem_password_cb *, void *);
int PEM_write_bio_X509(BIO *, X509 *);

int PEM_write_bio_PrivateKey(BIO *, EVP_PKEY *, const EVP_CIPHER *,
                             unsigned char *, int, pem_password_cb *, void *);

EVP_PKEY *PEM_read_bio_PrivateKey(BIO *, EVP_PKEY **, pem_password_cb *,
                                 void *);

int PEM_write_bio_X509_REQ(BIO *, X509_REQ *);

X509_REQ *PEM_read_bio_X509_REQ(BIO *, X509_REQ **, pem_password_cb *, void *);

X509_CRL *PEM_read_bio_X509_CRL(BIO *, X509_CRL **, pem_password_cb *, void *);

int PEM_write_bio_X509_CRL(BIO *, X509_CRL *);

DH *PEM_read_bio_DHparams(BIO *, DH **, pem_password_cb *, void *);

EVP_PKEY *PEM_read_bio_PUBKEY(BIO *, EVP_PKEY **, pem_password_cb *, void *);
int PEM_write_bio_PUBKEY(BIO *, EVP_PKEY *);
"""

CUSTOMIZATIONS = """
"""
