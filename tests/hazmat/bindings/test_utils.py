# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import os

import pytest

from cryptography.hazmat.bindings import utils


def test_create_modulename():
    cdef_source = "cdef sources go here"
    source = "source code"
    name = utils._create_modulename(cdef_source, source, "2.7")
    assert name == "_Cryptography_cffi_bcba7f4bx4a14b588"
    name = utils._create_modulename(cdef_source, source, "3.2")
    assert name == "_Cryptography_cffi_a7462526x4a14b588"


def test_implicit_compile_explodes():
    # This uses a random comment to make sure each test gets its own hash
    random_comment = binascii.hexlify(os.urandom(24))
    ffi = utils.build_ffi("/* %s */" % random_comment, "")

    with pytest.raises(RuntimeError):
        ffi.verifier.load_library()
