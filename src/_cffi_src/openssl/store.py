# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/store.h>
"""

TYPES = """
typedef ... OSSL_STORE_CTX;
typedef ... OSSL_STORE_post_process_info_fn;
typedef ... OSSL_STORE_INFO;
typedef ... OSSL_PARAM;
"""

FUNCTIONS = """
OSSL_STORE_CTX * OSSL_STORE_open(const char *, const UI_METHOD *,
                   void *, OSSL_STORE_post_process_info_fn, void *);
OSSL_STORE_CTX * OSSL_STORE_open_ex(const char *, OSSL_LIB_CTX *, const char *,
                   const UI_METHOD *, void *,
                   const OSSL_PARAM [],
                   OSSL_STORE_post_process_info_fn,
                   void *);
int OSSL_STORE_close(OSSL_STORE_CTX *);
const char *OSSL_STORE_INFO_type_string(int);

OSSL_STORE_INFO *OSSL_STORE_load(OSSL_STORE_CTX *);
void OSSL_STORE_INFO_free(OSSL_STORE_INFO *);
int OSSL_STORE_INFO_get_type(const OSSL_STORE_INFO *);
EVP_PKEY *OSSL_STORE_INFO_get0_PARAMS(const OSSL_STORE_INFO *);
EVP_PKEY *OSSL_STORE_INFO_get1_PARAMS(const OSSL_STORE_INFO *);
EVP_PKEY *OSSL_STORE_INFO_get0_PUBKEY(const OSSL_STORE_INFO *);
EVP_PKEY *OSSL_STORE_INFO_get1_PUBKEY(const OSSL_STORE_INFO *);
EVP_PKEY *OSSL_STORE_INFO_get0_PKEY(const OSSL_STORE_INFO *);
EVP_PKEY *OSSL_STORE_INFO_get1_PKEY(const OSSL_STORE_INFO *);
X509 *OSSL_STORE_INFO_get0_CERT(const OSSL_STORE_INFO *);
X509 *OSSL_STORE_INFO_get1_CERT(const OSSL_STORE_INFO *);
X509_CRL *OSSL_STORE_INFO_get0_CRL(const OSSL_STORE_INFO *);
X509_CRL *OSSL_STORE_INFO_get1_CRL(const OSSL_STORE_INFO *);
"""

CUSTOMIZATIONS = """
"""
