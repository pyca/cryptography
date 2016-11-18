# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/opensslv.h>
/*
    LibreSSL removed e_os2.h from the public headers so we'll only include it
    if we're using vanilla OpenSSL.
*/
#if !defined(LIBRESSL_VERSION_NUMBER)
#include <openssl/e_os2.h>
#endif
#if defined(_WIN32)
#include <windows.h>
#endif

#define CRYPTOGRAPHY_OPENSSL_102_OR_GREATER \
    (OPENSSL_VERSION_NUMBER >= 0x10002000)
#define CRYPTOGRAPHY_OPENSSL_102BETA2_OR_GREATER \
    (OPENSSL_VERSION_NUMBER >= 0x10002002)
#define CRYPTOGRAPHY_OPENSSL_110_OR_GREATER \
    (OPENSSL_VERSION_NUMBER >= 0x10100000)

#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_102 \
    (OPENSSL_VERSION_NUMBER < 0x10002000)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_102BETA3 \
    (OPENSSL_VERSION_NUMBER < 0x10002003)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_102I \
    (OPENSSL_VERSION_NUMBER < 0x1000209fL)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_110 \
    (OPENSSL_VERSION_NUMBER < 0x10100000)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_110PRE4 \
    (OPENSSL_VERSION_NUMBER < 0x10100004)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_110PRE5 \
    (OPENSSL_VERSION_NUMBER < 0x10100005)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_110PRE6 \
    (OPENSSL_VERSION_NUMBER < 0x10100006)

#if defined(LIBRESSL_VERSION_NUMBER)
#define CRYPTOGRAPHY_IS_LIBRESSL 1
#else
#define CRYPTOGRAPHY_IS_LIBRESSL 0
#endif
"""

TYPES = """
static const int CRYPTOGRAPHY_OPENSSL_110_OR_GREATER;

static const int CRYPTOGRAPHY_OPENSSL_LESS_THAN_102I;

static const int CRYPTOGRAPHY_IS_LIBRESSL;
"""

FUNCTIONS = """
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""
