# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
/* define our OpenSSL API compatibility level to 1.0.1. Any symbols older than
   that will raise an error during compilation. We can raise this number again
   after we drop 1.0.2 support in the distant future.  */
#define OPENSSL_API_COMPAT 0x10001000L

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Wincrypt.h>
#include <Winsock2.h>
/*
    undef some macros that are defined by wincrypt.h but are also types in
    boringssl. openssl has worked around this but boring has not yet. see:
    https://chromium.googlesource.com/chromium/src/+/refs/heads/main/base
    /win/wincrypt_shim.h
*/
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_SIGNER_INFO
#endif

#include <openssl/opensslv.h>


#if defined(LIBRESSL_VERSION_NUMBER)
#define CRYPTOGRAPHY_IS_LIBRESSL 1
#else
#define CRYPTOGRAPHY_IS_LIBRESSL 0
#endif

#if defined(OPENSSL_IS_BORINGSSL)
#define CRYPTOGRAPHY_IS_BORINGSSL 1
#else
#define CRYPTOGRAPHY_IS_BORINGSSL 0
#endif

#if CRYPTOGRAPHY_IS_LIBRESSL
#define CRYPTOGRAPHY_LIBRESSL_LESS_THAN_350 \
    (LIBRESSL_VERSION_NUMBER < 0x3050000f)
#define CRYPTOGRAPHY_LIBRESSL_LESS_THAN_360 \
    (LIBRESSL_VERSION_NUMBER < 0x3060000f)

#else
#define CRYPTOGRAPHY_LIBRESSL_LESS_THAN_350 (0)
#define CRYPTOGRAPHY_LIBRESSL_LESS_THAN_360 (0)
#endif

#if OPENSSL_VERSION_NUMBER < 0x10101000
    #error "pyca/cryptography MUST be linked with Openssl 1.1.1 or later"
#endif

#define CRYPTOGRAPHY_OPENSSL_111D_OR_GREATER \
    (OPENSSL_VERSION_NUMBER >= 0x10101040 && !CRYPTOGRAPHY_IS_LIBRESSL)
#define CRYPTOGRAPHY_OPENSSL_300_OR_GREATER \
    (OPENSSL_VERSION_NUMBER >= 0x30000000 && !CRYPTOGRAPHY_IS_LIBRESSL)

#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_111B \
    (OPENSSL_VERSION_NUMBER < 0x10101020 || CRYPTOGRAPHY_IS_LIBRESSL)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_111D \
    (OPENSSL_VERSION_NUMBER < 0x10101040 || CRYPTOGRAPHY_IS_LIBRESSL)
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_111E \
    (OPENSSL_VERSION_NUMBER < 0x10101050 || CRYPTOGRAPHY_IS_LIBRESSL)
#if (CRYPTOGRAPHY_OPENSSL_LESS_THAN_111D && !CRYPTOGRAPHY_IS_LIBRESSL && \
    !defined(OPENSSL_NO_ENGINE)) || defined(USE_OSRANDOM_RNG_FOR_TESTING)
#define CRYPTOGRAPHY_NEEDS_OSRANDOM_ENGINE 1
#else
#define CRYPTOGRAPHY_NEEDS_OSRANDOM_ENGINE 0
#endif
"""

TYPES = """
static const int CRYPTOGRAPHY_OPENSSL_111D_OR_GREATER;
static const int CRYPTOGRAPHY_OPENSSL_300_OR_GREATER;

static const int CRYPTOGRAPHY_OPENSSL_LESS_THAN_111B;
static const int CRYPTOGRAPHY_OPENSSL_LESS_THAN_111E;
static const int CRYPTOGRAPHY_NEEDS_OSRANDOM_ENGINE;

static const int CRYPTOGRAPHY_LIBRESSL_LESS_THAN_350;

static const int CRYPTOGRAPHY_IS_LIBRESSL;
static const int CRYPTOGRAPHY_IS_BORINGSSL;
"""

FUNCTIONS = """
"""

CUSTOMIZATIONS = """
"""
