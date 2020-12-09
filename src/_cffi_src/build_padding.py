# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import os

from _cffi_src.utils import build_ffi, compiler_type, extra_link_args


with open(
    os.path.join(os.path.dirname(__file__), "hazmat_src/padding.h")
) as f:
    types = f.read()

with open(
    os.path.join(os.path.dirname(__file__), "hazmat_src/padding.c")
) as f:
    functions = f.read()

ffi = build_ffi(
    module_name="_padding",
    cdef_source=types,
    verify_source=functions,
    extra_link_args=extra_link_args(compiler_type()),
)
