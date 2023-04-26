# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/dh.h>
"""

TYPES = """
typedef ... DH;

const long DH_NOT_SUITABLE_GENERATOR;
"""

FUNCTIONS = """
void DH_free(DH *);
"""

CUSTOMIZATIONS = """
"""
