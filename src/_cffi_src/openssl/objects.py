# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/objects.h>
"""

TYPES = """
"""

FUNCTIONS = """
const char *OBJ_nid2ln(int);
const char *OBJ_nid2sn(int);
int OBJ_obj2nid(const ASN1_OBJECT *);
int OBJ_txt2nid(const char *);
"""

CUSTOMIZATIONS = """
"""
