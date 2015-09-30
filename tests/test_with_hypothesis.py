from hypothesis import given
from hypothesis.strategies import binary

import pytest

from cryptography.fernet import Fernet


hypothesis = pytest.importorskip("hypothesis")


@given(binary())
def test_fernet(data):
    f = Fernet(Fernet.generate_key())
    ct = f.encrypt(data)
    assert f.decrypt(ct) == data
