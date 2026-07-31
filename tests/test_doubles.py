# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import copy

import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .doubles import DummyEd25519PublicKey, DummyRSAPrivateKey


class TestDummyEd25519PublicKey:
    def test_public_bytes(self):
        key = DummyEd25519PublicKey(b"test data")
        # The encoding and format arguments are ignored by this dummy
        assert (
            key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            == b"test data"
        )

    def test_public_bytes_raw_not_implemented(self):
        key = DummyEd25519PublicKey(b"test data")
        with pytest.raises(NotImplementedError):
            key.public_bytes_raw()

    def test_verify_not_implemented(self):
        key = DummyEd25519PublicKey(b"test data")
        with pytest.raises(NotImplementedError):
            key.verify(b"sig", b"data")

    def test_eq_not_implemented(self):
        key = DummyEd25519PublicKey(b"test data")
        with pytest.raises(NotImplementedError):
            key == key

    def test_copy_not_implemented(self):
        key = DummyEd25519PublicKey(b"test data")
        with pytest.raises(NotImplementedError):
            copy.copy(key)

    def test_deepcopy_not_implemented(self):
        key = DummyEd25519PublicKey(b"test data")
        with pytest.raises(NotImplementedError):
            copy.deepcopy(key)


class TestDummyRSAPrivateKey:
    def test_decrypt(self):
        key = DummyRSAPrivateKey()
        with pytest.raises(TypeError):
            key.decrypt(b"ciphertext", padding.PKCS1v15())

    def test_key_size_not_implemented(self):
        key = DummyRSAPrivateKey()
        with pytest.raises(NotImplementedError):
            key.key_size

    def test_public_key_not_implemented(self):
        key = DummyRSAPrivateKey()
        with pytest.raises(NotImplementedError):
            key.public_key()

    def test_sign_not_implemented(self):
        key = DummyRSAPrivateKey()
        with pytest.raises(NotImplementedError):
            key.sign(b"data", padding.PKCS1v15(), hashes.SHA256())

    def test_private_numbers_not_implemented(self):
        key = DummyRSAPrivateKey()
        with pytest.raises(NotImplementedError):
            key.private_numbers()

    def test_private_bytes_not_implemented(self):
        key = DummyRSAPrivateKey()
        with pytest.raises(NotImplementedError):
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )

    def test_copy_not_implemented(self):
        key = DummyRSAPrivateKey()
        with pytest.raises(NotImplementedError):
            copy.copy(key)

    def test_deepcopy_not_implemented(self):
        key = DummyRSAPrivateKey()
        with pytest.raises(NotImplementedError):
            copy.deepcopy(key)
