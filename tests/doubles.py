# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from cryptography.hazmat.primitives.ciphers import (
    BlockCipherAlgorithm,
    CipherAlgorithm,
)
from cryptography.hazmat.primitives.ciphers.modes import Mode
from cryptography.utils import Buffer


class DummyCipherAlgorithm(CipherAlgorithm):
    name = "dummy-cipher"
    block_size = 128
    key_size = 256
    key_sizes = frozenset([256])


class DummyBlockCipherAlgorithm(DummyCipherAlgorithm, BlockCipherAlgorithm):
    def __init__(self, _: object) -> None:
        pass

    name = "dummy-block-cipher"


class DummyMode(Mode):
    name = "dummy-mode"

    def validate_for_algorithm(self, algorithm: CipherAlgorithm) -> None:
        pass


class DummyHashAlgorithm(hashes.HashAlgorithm):
    name = "dummy-hash"
    block_size = None

    def __init__(self, digest_size: int = 32) -> None:
        self._digest_size = digest_size

    @property
    def digest_size(self) -> int:
        return self._digest_size


class DummyKeySerializationEncryption(
    serialization.KeySerializationEncryption
):
    pass


class DummyAsymmetricPadding(padding.AsymmetricPadding):
    name = "dummy-padding"


class DummyEd25519PublicKey(ed25519.Ed25519PublicKey):
    """
    A fake Ed25519PublicKey that returns fixed data from public_bytes().
    Used for testing invalid key encodings.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        return self._data

    def public_bytes_raw(self) -> bytes:
        raise NotImplementedError

    def verify(self, signature: Buffer, data: Buffer) -> None:
        raise NotImplementedError

    def __eq__(self, other: object) -> bool:
        raise NotImplementedError

    def __copy__(self) -> ed25519.Ed25519PublicKey:
        raise NotImplementedError

    def __deepcopy__(self, memo: dict) -> ed25519.Ed25519PublicKey:
        raise NotImplementedError
