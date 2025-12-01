# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import copy

import pytest

from cryptography.hazmat.primitives import serialization

from .doubles import DummyEd25519PublicKey


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
