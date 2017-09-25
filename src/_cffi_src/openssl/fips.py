# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/crypto.h>
"""

TYPES = """
static const long Cryptography_HAS_FIPS;
"""

FUNCTIONS = """
int FIPS_mode_set(int);
int FIPS_mode(void);
void FIPS_selftest_check(void);
"""

CUSTOMIZATIONS = """
#ifdef OPENSSL_FIPS
static const long Cryptography_HAS_FIPS = 1;
# else
static const long Cryptography_HAS_FIPS = 0;
int (*FIPS_mode_set)(int) = NULL;
int (*FIPS_mode)(void) = NULL;
void (*FIPS_selftest_check)(void) = NULL;
#endif
"""
