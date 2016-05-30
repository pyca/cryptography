# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import sys

from _cffi_src.utils import (
    build_ffi_for_binding, compiler_type, extra_link_args
)


def _get_openssl_libraries(platform):
    # OpenSSL goes by a different library name on different operating systems.
    if platform == "darwin":
        return _osx_libraries(
            os.environ.get("CRYPTOGRAPHY_OSX_NO_LINK_FLAGS")
        )
    elif platform == "win32":
        return ["libeay32", "ssleay32", "advapi32",
                "crypt32", "gdi32", "user32", "ws2_32"]
    else:
        # In some circumstances, the order in which these libs are
        # specified on the linker command-line is significant;
        # libssl must come before libcrypto
        # (http://marc.info/?l=openssl-users&m=135361825921871)
        return ["ssl", "crypto"]


def _osx_libraries(build_static):
    # For building statically we don't want to pass the -lssl or -lcrypto flags
    if build_static == "1":
        return []
    else:
        return ["ssl", "crypto"]


_PRE_INCLUDE = """
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
"""


ffi = build_ffi_for_binding(
    module_name="_openssl",
    module_prefix="_cffi_src.openssl.",
    modules=[
        "aes",
        "asn1",
        "bignum",
        "bio",
        "cmac",
        "cms",
        "crypto",
        "dh",
        "dsa",
        "ec",
        "ecdh",
        "ecdsa",
        "engine",
        "err",
        "evp",
        "hmac",
        "nid",
        "objects",
        "ocsp",
        "opensslv",
        "pem",
        "pkcs12",
        "rand",
        "rsa",
        "ssl",
        "x509",
        "x509name",
        "x509v3",
        "x509_vfy",
        "pkcs7",
        "callbacks",
    ],
    pre_include=_PRE_INCLUDE,
    libraries=_get_openssl_libraries(sys.platform),
    extra_link_args=extra_link_args(compiler_type()),
)
