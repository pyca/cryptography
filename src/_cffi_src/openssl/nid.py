# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/obj_mac.h>
"""

TYPES = """
static const int NID_undef;

static const int NID_subject_alt_name;
static const int NID_crl_reason;
"""

FUNCTIONS = """
"""

CUSTOMIZATIONS = """
"""
