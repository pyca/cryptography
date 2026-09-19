# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/dsa.h>
"""

TYPES = """
typedef ... DSA;
"""

FUNCTIONS = """
int DSA_generate_key(DSA *);
DSA *DSA_new(void);
void DSA_free(DSA *);

int DSA_generate_parameters_ex(DSA *, int, unsigned char *, int,
                               int *, unsigned long *, BN_GENCB *);
"""

CUSTOMIZATIONS = """
"""
