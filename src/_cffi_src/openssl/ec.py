# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
"""

TYPES = """
typedef ... EC_KEY;
typedef ... EC_GROUP;
typedef ... EC_POINT;
typedef struct {
    int nid;
    const char *comment;
} EC_builtin_curve;
"""

FUNCTIONS = """
size_t EC_get_builtin_curves(EC_builtin_curve *, size_t);

void EC_KEY_free(EC_KEY *);

EC_KEY *EC_KEY_new_by_curve_name(int);

const char *EC_curve_nid2nist(int);
"""

CUSTOMIZATIONS = """
"""
