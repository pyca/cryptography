# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

with open(os.path.join(
    os.path.dirname(__file__), "src/osrandom_engine.h"
)) as f:
    INCLUDES = f.read()

TYPES = """
static const char *const Cryptography_osrandom_engine_name;
static const char *const Cryptography_osrandom_engine_id;
"""

FUNCTIONS = """
int Cryptography_add_osrandom_engine(void);
"""

MACROS = """
"""

with open(os.path.join(
    os.path.dirname(__file__), "src/osrandom_engine.c"
)) as f:
    CUSTOMIZATIONS = f.read()

CONDITIONAL_NAMES = {}
