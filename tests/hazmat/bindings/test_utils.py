# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
