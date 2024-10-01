# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import json
import os

import pytest

import cryptography_vectors
from cryptography.hazmat.primitives.nonces import Nonce, Nonces

vector_file = cryptography_vectors.open_vector_file(
    os.path.join("nonces", "nonces.json"), "r"
)
VECTORS = json.load(vector_file)
for i in VECTORS:
    i["size"] = int(i["size"])
    i["counter_size"] = int(i["counter_size"])
    i["seed"] = bytes.fromhex(i["seed"])
    i["nonce"] = bytes.fromhex(i["nonce"])


class TestNonce:
    @pytest.mark.parametrize("vector", VECTORS)
    def test_from_bytes(self, vector):
        nonce_bytes = b"\xa0" * vector["size"]
        nonce = Nonce.from_bytes(nonce_bytes)
        assert nonce == nonce_bytes
        assert isinstance(nonce, Nonce)
        assert isinstance(nonce, bytes)

    @pytest.mark.parametrize("vector", VECTORS)
    def test_random(self, vector):
        nonce = Nonce.random(vector["size"])
        assert isinstance(nonce, Nonce)
        assert isinstance(nonce, bytes)

    def test_bad_params(self):
        with pytest.raises(TypeError):
            Nonce.from_bytes("test")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            Nonce.random("test")  # type: ignore[arg-type]


class TestNonces:
    @pytest.mark.parametrize("vector", VECTORS)
    def test_params(self, vector):
        nonce = Nonce.from_bytes(vector["nonce"])
        nonces = Nonces(
            vector["size"],
            vector["counter_size"],
            vector["seed"],
            vector["order"],
            vector["trailing_counter"],
        )
        assert nonces.update() == nonce
        assert bytes(nonces) == nonce

    @pytest.mark.parametrize("vector", VECTORS)
    def test_overflow(self, vector):
        nonces = Nonces(vector["size"], vector["counter_size"])
        nonces.set_counter(nonces.max_counter)
        with pytest.raises(OverflowError):
            nonces.update()

    def test_bad_params(self):
        with pytest.raises(TypeError):
            Nonces("test", 4)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            Nonces(0, 0)
        with pytest.raises(TypeError):
            Nonces(8, "test")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            Nonces(8, 9)
        with pytest.raises(TypeError):
            Nonces(8, 4, "test")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            Nonces(8, 4, b"\x00" * 4, None)
        with pytest.raises(ValueError):
            Nonces(8, 4, b"\x00" * 4, "test")
        with pytest.raises(TypeError):
            Nonces(8, 4, b"\x00" * 4, "big", None)
        with pytest.raises(ValueError):
            Nonces(8, 4, b"\x00" * 5, "big", True)

    @pytest.mark.parametrize("vector", VECTORS)
    def test_set_counter(self, vector):
        nonces = Nonces(vector["size"], vector["counter_size"])
        with pytest.raises(TypeError):
            nonces.set_counter("test")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            nonces.set_counter(nonces.max_counter + 1)
        nonces.set_counter(nonces.max_counter)
        with pytest.raises(AssertionError):
            nonces.set_counter(0)

    @pytest.mark.parametrize("vector", VECTORS)
    def test_increment_setter(self, vector):
        nonces = Nonces(vector["size"], vector["counter_size"])
        nonces.update()
        with pytest.raises(TypeError):
            nonces.increment = "test"  # type: ignore[assignment]
        with pytest.raises(ValueError):
            nonces.increment = 0
        with pytest.raises(ValueError):
            nonces.increment = -1
        with pytest.raises(ValueError):
            nonces.increment = nonces.max_counter
        nonces.set_counter(nonces.max_counter - 2)
        nonces.increment = 2
        nonces.update()
        assert nonces.counter == nonces.max_counter

    @pytest.mark.parametrize("vector", VECTORS)
    def test_properties(self, vector):
        nonces = Nonces(vector["size"], vector["counter_size"])
        nonces.update()
        assert isinstance(nonces.counter_bytes, bytes)
        assert isinstance(nonces.seed_bytes, bytes)
        assert isinstance(nonces.nonce, bytes)
        assert isinstance(nonces.increment, int)
        assert isinstance(nonces.counter, int)
        assert isinstance(nonces.max_counter, int)
        assert isinstance(nonces.size, int)
        assert isinstance(nonces.counter_size, int)
        assert isinstance(nonces.seed_size, int)
        assert isinstance(nonces.order, str)
