# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

from cryptography.hazmat.primitives._cipheralgorithm import (
    BlockCipherAlgorithm,
    _verify_key_size,
)


class Blowfish(BlockCipherAlgorithm):
    name = "Blowfish"
    block_size = 64
    key_sizes = frozenset(range(32, 449, 8))

    def __init__(self, key: bytes):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self) -> int:
        return len(self.key) * 8


class CAST5(BlockCipherAlgorithm):
    name = "CAST5"
    block_size = 64
    key_sizes = frozenset(range(40, 129, 8))

    def __init__(self, key: bytes):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self) -> int:
        return len(self.key) * 8


class SEED(BlockCipherAlgorithm):
    name = "SEED"
    block_size = 128
    key_sizes = frozenset([128])

    def __init__(self, key: bytes):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self) -> int:
        return len(self.key) * 8


class IDEA(BlockCipherAlgorithm):
    name = "IDEA"
    block_size = 64
    key_sizes = frozenset([128])

    def __init__(self, key: bytes):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self) -> int:
        return len(self.key) * 8
