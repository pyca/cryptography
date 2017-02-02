# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils


def test_int_from_bytes_bytearray():
    assert utils.int_from_bytes(bytearray(b"\x02\x10"), "big") == 528
