# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#define CRYPTOGRAPHY_OPENSSL_101_OR_GREATER \
    (OPENSSL_VERSION_NUMBER >= 0x10001000)
#define CRYPTOGRAPHY_OPENSSL_102_OR_GREATER \
    (OPENSSL_VERSION_NUMBER >= 0x10002000)
#define CRYPTOGRAPHY_OPENSSL_110_OR_GREATER \
    (OPENSSL_VERSION_NUMBER >= 0x10100000)

#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_101 \
    (OPENSSL_VERSION_NUMBER < 0x10001000)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_102 \
    (OPENSSL_VERSION_NUMBER < 0x10002000)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_110 \
    (OPENSSL_VERSION_NUMBER < 0x10100000)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_110PRE5 \
    (OPENSSL_VERSION_NUMBER < 0x10100005)
"""

TYPES = """
static const int CRYPTOGRAPHY_OPENSSL_LESS_THAN_101;
"""

FUNCTIONS = """
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""
