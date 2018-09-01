# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
/* define our OpenSSL API compatibility level to 1.0.1. Any symbols older than
   that will raise an error during compilation. We can raise this number again
   after we drop 1.0.2 support in the distant future.  */
#define OPENSSL_API_COMPAT 0x10001000L

#include <openssl/opensslv.h>


#if defined(LIBRESSL_VERSION_NUMBER)
#define CRYPTOGRAPHY_IS_LIBRESSL 1
#else
#define CRYPTOGRAPHY_IS_LIBRESSL 0
#endif

/*
    LibreSSL removed e_os2.h from the public headers so we'll only include it
    if we're using vanilla OpenSSL.
*/
#if !CRYPTOGRAPHY_IS_LIBRESSL
#include <openssl/e_os2.h>
#endif
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Wincrypt.h>
#include <Winsock2.h>
#endif

#define CRYPTOGRAPHY_LIBRESSL_27_OR_GREATER \
    (CRYPTOGRAPHY_IS_LIBRESSL && LIBRESSL_VERSION_NUMBER >= 0x2070000fL)

#define CRYPTOGRAPHY_OPENSSL_102_OR_GREATER \
    (OPENSSL_VERSION_NUMBER >= 0x10002000 && !CRYPTOGRAPHY_IS_LIBRESSL)
#define CRYPTOGRAPHY_OPENSSL_102L_OR_GREATER \
    (OPENSSL_VERSION_NUMBER >= 0x100020cf && !CRYPTOGRAPHY_IS_LIBRESSL)
#define CRYPTOGRAPHY_OPENSSL_110_OR_GREATER \
    (OPENSSL_VERSION_NUMBER >= 0x10100000 && !CRYPTOGRAPHY_IS_LIBRESSL)
#define CRYPTOGRAPHY_OPENSSL_110F_OR_GREATER \
    (OPENSSL_VERSION_NUMBER >= 0x1010006f && !CRYPTOGRAPHY_IS_LIBRESSL)
#define CRYPTOGRAPHY_OPENSSL_BETWEEN_111_and_111PRE9 \
    (OPENSSL_VERSION_NUMBER >= 0x10101000 && \
     OPENSSL_VERSION_NUMBER <= 0x10101009)

#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_102 \
    (OPENSSL_VERSION_NUMBER < 0x10002000 || CRYPTOGRAPHY_IS_LIBRESSL)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_102I \
    (OPENSSL_VERSION_NUMBER < 0x1000209f || CRYPTOGRAPHY_IS_LIBRESSL)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_110 \
    (OPENSSL_VERSION_NUMBER < 0x10100000 || CRYPTOGRAPHY_IS_LIBRESSL)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_110J \
    (OPENSSL_VERSION_NUMBER < 0x101000af || CRYPTOGRAPHY_IS_LIBRESSL)
"""

TYPES = """
static const int CRYPTOGRAPHY_OPENSSL_102L_OR_GREATER;
static const int CRYPTOGRAPHY_OPENSSL_110_OR_GREATER;
static const int CRYPTOGRAPHY_OPENSSL_110F_OR_GREATER;

static const int CRYPTOGRAPHY_OPENSSL_LESS_THAN_102I;
static const int CRYPTOGRAPHY_OPENSSL_LESS_THAN_102;

static const int CRYPTOGRAPHY_IS_LIBRESSL;
"""

FUNCTIONS = """
"""

CUSTOMIZATIONS = """
"""
