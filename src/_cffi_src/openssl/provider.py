# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

includes = """
#include <openssl/provider.h>
"""

TYPES = """
typedef ... OSSL_PROVIDER;
"""

FUNCTIONS = """
OSSL_PROVIDER *OSSL_PROVIDER_load(OSSL_LIB_CTX *, const char *);
OSSL_PROVIDER *OSSL_PROVIDER_try_load(OSSL_LIB_CTX *, const char *, int);
int OSSL_PROVIDER_unload(OSSL_PROVIDER *);
int OSSL_PROVIDER_available(OSSL_LIB_CTX *, const char *);
"""

CUSTOMIZATIONS = """
"""
