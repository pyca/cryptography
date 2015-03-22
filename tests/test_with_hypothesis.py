import pytest

from cryptography.fernet import Fernet

hypothesis = pytest.importorskip("hypothesis")


@hypothesis.given(bytes)
def test_fernet(data):
    f = Fernet(Fernet.generate_key())
    ct = f.encrypt(data)
    assert f.decrypt(ct) == data
