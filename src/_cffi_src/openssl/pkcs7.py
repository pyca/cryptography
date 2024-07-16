# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/pkcs7.h>
"""

TYPES = """
typedef ... PKCS7;
"""

FUNCTIONS = """
void PKCS7_free(PKCS7 *);
PKCS7 *SMIME_read_PKCS7(BIO *, BIO **);
"""

CUSTOMIZATIONS = """
"""
