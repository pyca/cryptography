# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from hypothesis import HealthCheck, given, settings
from hypothesis.strategies import binary

from cryptography.fernet import Fernet


@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(binary())
def test_fernet(data):
    f = Fernet(Fernet.generate_key())
    ct = f.encrypt(data)
    assert f.decrypt(ct) == data
