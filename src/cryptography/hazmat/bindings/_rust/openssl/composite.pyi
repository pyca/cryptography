# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.primitives import _serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from cryptography.utils import Buffer

class MLDSA44Ed25519PrivateKey:
    def __init__(
        self,
        mldsa_key: mldsa.MLDSA44PrivateKey,
        ed25519_key: ed25519.Ed25519PrivateKey,
    ) -> None: ...
    def public_key(self) -> MLDSA44Ed25519PublicKey: ...
    def sign(self, data: Buffer, context: Buffer | None = None) -> bytes: ...
    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes: ...
    def private_bytes_raw(self) -> bytes: ...

class MLDSA44Ed25519PublicKey:
    def __init__(
        self,
        mldsa_key: mldsa.MLDSA44PublicKey,
        ed25519_key: ed25519.Ed25519PublicKey,
    ) -> None: ...
    def verify(
        self,
        signature: Buffer,
        data: Buffer,
        context: Buffer | None = None,
    ) -> None: ...
    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes: ...
    def public_bytes_raw(self) -> bytes: ...
    def __eq__(self, other: object) -> bool: ...
