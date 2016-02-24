# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from hypothesis import given
from hypothesis.strategies import binary

from cryptography.fernet import Fernet


@given(binary())
def test_fernet(data):
    f = Fernet(Fernet.generate_key())
    ct = f.encrypt(data)
    assert f.decrypt(ct) == data
