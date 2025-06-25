# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/crypto.h>
"""

TYPES = """
typedef ... OSSL_LIB_CTX;
"""

FUNCTIONS = """
OSSL_LIB_CTX *OSSL_LIB_CTX_new(void);
void OSSL_LIB_CTX_free(OSSL_LIB_CTX *);
"""

CUSTOMIZATIONS = """
"""
