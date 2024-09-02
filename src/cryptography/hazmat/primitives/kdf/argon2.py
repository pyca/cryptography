# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

from cryptography import utils
from cryptography.exceptions import (
    AlreadyFinalized,
    InvalidKey,
    UnsupportedAlgorithm,
)
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.kdf import KeyDerivationFunction


class Argon2id(KeyDerivationFunction):
    def __init__(
        self,
        *,
        salt: bytes,
        length: int,
        iterations: int,
        lanes: int,
        memory_cost: int,
        ad: bytes | None = None,
        secret: bytes | None = None,
    ):
        from cryptography.hazmat.backends.openssl.backend import (
            backend as ossl,
        )

        if not ossl.argon2_supported():
            raise UnsupportedAlgorithm(
                "This version of OpenSSL does not support argon2id"
            )

        utils._check_bytes("salt", salt)
        # OpenSSL requires a salt of at least 8 bytes
        if len(salt) < 8:
            raise ValueError("salt must be at least 8 bytes")
        # Minimum length is 4 bytes as specified in RFC 9106
        if not isinstance(length, int) or length < 4:
            raise ValueError("length must be an integer greater >= 4")
        if not isinstance(iterations, int) or iterations < 1:
            raise ValueError("iterations must be an integer greater than 0")
        if not isinstance(lanes, int) or lanes < 1:
            raise ValueError("lanes must be an integer greater than 0")
        # Memory cost must be at least 8 * lanes
        if not isinstance(memory_cost, int) or memory_cost < 8 * lanes:
            raise ValueError("memory_cost must be an integer >= 8 * lanes")
        if ad is not None:
            utils._check_bytes("ad", ad)
        if secret is not None:
            utils._check_bytes("secret", secret)

        self._used = False
        self._salt = salt
        self._length = length
        self._iterations = iterations
        self._lanes = lanes
        self._memory_cost = memory_cost
        self._ad = ad
        self._secret = secret

    def derive(self, key_material: bytes) -> bytes:
        if self._used:
            raise AlreadyFinalized("argon2id instances can only be used once.")
        self._used = True

        utils._check_byteslike("key_material", key_material)

        return rust_openssl.kdf.derive_argon2id(
            key_material,
            self._salt,
            self._length,
            self._iterations,
            self._lanes,
            self._memory_cost,
            self._ad,
            self._secret,
        )

    def verify(self, key_material: bytes, expected_key: bytes) -> None:
        if not constant_time.bytes_eq(self.derive(key_material), expected_key):
            raise InvalidKey
