# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/provider.h>
"""

TYPES = """
typedef ... OSSL_PROVIDER;
"""

FUNCTIONS = """
int OSSL_PROVIDER_set_default_search_path(OSSL_LIB_CTX *, const char *);

OSSL_PROVIDER *OSSL_PROVIDER_load(OSSL_LIB_CTX *, const char *);
OSSL_PROVIDER *OSSL_PROVIDER_try_load(OSSL_LIB_CTX *, const char *, int);
int OSSL_PROVIDER_unload(OSSL_PROVIDER *);
"""

CUSTOMIZATIONS = """

#if CRYPTOGRAPHY_IS_LIBRESSL || CRYPTOGRAPHY_IS_BORINGSSL \
    || CRYPTOGRAPHY_IS_AWSLC
int (*OSSL_PROVIDER_set_default_search_path)(OSSL_LIB_CTX *,
      const char *) = NULL;

OSSL_PROVIDER *(*OSSL_PROVIDER_load)(OSSL_LIB_CTX *, const char *) = NULL;
OSSL_PROVIDER *(*OSSL_PROVIDER_try_load)(OSSL_LIB_CTX *,
                 const char *, int) = NULL;
int (*OSSL_PROVIDER_unload)(OSSL_PROVIDER *) = NULL;
#endif
"""
