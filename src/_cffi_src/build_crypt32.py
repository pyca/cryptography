# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from _cffi_src.utils import build_ffi_for_binding


ffi = build_ffi_for_binding(
    module_name="_crypt32",
    module_prefix="_cffi_src.crypt32.",
    modules=[
        "crypt32",
    ],
    libraries=[
        "crypt32",
    ],
)
