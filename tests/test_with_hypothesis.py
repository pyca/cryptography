from hypothesis import given
from hypothesis.strategies import binary

from cryptography.fernet import Fernet


@given(binary())
def test_fernet(data):
    f = Fernet(Fernet.generate_key())
    ct = f.encrypt(data)
    assert f.decrypt(ct) == data
