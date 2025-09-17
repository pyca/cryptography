# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = r"""
/* define our OpenSSL API compatibility level to 3.0.0. Any symbols older than
   that will raise an error during compilation. */
#define OPENSSL_API_COMPAT 0x30000000L

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
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

#if defined(OPENSSL_IS_AWSLC)
#define CRYPTOGRAPHY_IS_AWSLC 1
#else
#define CRYPTOGRAPHY_IS_AWSLC 0
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
#define CRYPTOGRAPHY_OPENSSL_320_OR_GREATER 1
#else
#define CRYPTOGRAPHY_OPENSSL_320_OR_GREATER 0
#endif

#if !CRYPTOGRAPHY_IS_LIBRESSL && !CRYPTOGRAPHY_IS_BORINGSSL && \
    !CRYPTOGRAPHY_IS_AWSLC
    #if OPENSSL_VERSION_NUMBER < 0x30000000
        #error "pyca/cryptography MUST be linked with OpenSSL 3.0.0 or later"
    #endif
#endif
"""

TYPES = """
"""

FUNCTIONS = """
"""

CUSTOMIZATIONS = """
"""
