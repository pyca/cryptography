# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from hypothesis import given
from hypothesis.strategies import binary

from cryptography.hazmat.primitives.padding import PKCS7


@given(binary())
def test_pkcs7(data):
    # TODO: add additional tests with arbitrary block sizes
    p = PKCS7(block_size=128)
    padder = p.padder()
    unpadder = p.unpadder()

    padded = padder.update(data) + padder.finalize()

    assert unpadder.update(padded) + unpadder.finalize() == data
