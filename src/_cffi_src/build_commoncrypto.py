# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from _cffi_src.utils import build_ffi_for_binding


ffi = build_ffi_for_binding(
    module_name="_commoncrypto",
    module_prefix="_cffi_src.commoncrypto.",
    modules=[
        "cf",
        "common_digest",
        "common_hmac",
        "common_key_derivation",
        "common_cryptor",
        "common_symmetric_key_wrap",
        "secimport",
        "secitem",
        "seckey",
        "seckeychain",
        "sectransform",
    ],
    extra_link_args=[
        "-framework", "Security", "-framework", "CoreFoundation"
    ],
)
