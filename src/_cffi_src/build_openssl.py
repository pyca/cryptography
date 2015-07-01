# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import sys

from _cffi_src.utils import build_ffi_for_binding, extra_link_args


def _get_openssl_libraries(platform):
    # OpenSSL goes by a different library name on different operating systems.
    if platform != "win32":
        # In some circumstances, the order in which these libs are
        # specified on the linker command-line is significant;
        # libssl must come before libcrypto
        # (http://marc.info/?l=openssl-users&m=135361825921871)
        return ["ssl", "crypto"]
    else:
        link_type = os.environ.get("PYCA_WINDOWS_LINK_TYPE", "static")
        return _get_openssl_windows_libraries(link_type)


def _get_openssl_windows_libraries(link_type):
    if link_type == "dynamic":
        return ["libeay32", "ssleay32", "advapi32"]
    elif link_type == "static" or link_type == "":
        return ["libeay32mt", "ssleay32mt", "advapi32",
                "crypt32", "gdi32", "user32", "ws2_32"]
    else:
        raise ValueError(
            "PYCA_WINDOWS_LINK_TYPE must be 'static' or 'dynamic'"
        )


_OSX_PRE_INCLUDE = """
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#define __ORIG_DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER \
    DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#undef DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif
"""

_OSX_POST_INCLUDE = """
#ifdef __APPLE__
#undef DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER \
    __ORIG_DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
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
        "conf",
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
        "opensslv",
        "pem",
        "pkcs7",
        "pkcs12",
        "rand",
        "rsa",
        "ssl",
        "x509",
        "x509name",
        "x509v3",
        "x509_vfy"
    ],
    pre_include=_OSX_PRE_INCLUDE,
    post_include=_OSX_POST_INCLUDE,
    libraries=_get_openssl_libraries(sys.platform),
    extra_link_args=extra_link_args(sys.platform),
)
