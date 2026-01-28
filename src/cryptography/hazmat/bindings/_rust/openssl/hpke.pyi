# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.utils import Buffer

class KEM:
    X25519: KEM
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class KDF:
    HKDF_SHA256: KDF
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class AEAD:
    AES_128_GCM: AEAD
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class Suite:
    def __init__(self, kem: KEM, kdf: KDF, aead: AEAD) -> None: ...
    def encrypt(
        self,
        plaintext: Buffer,
        public_key: x25519.X25519PublicKey,
        info: Buffer | None = None,
        aad: Buffer | None = None,
    ) -> bytes: ...
    def decrypt(
        self,
        ciphertext: Buffer,
        private_key: x25519.X25519PrivateKey,
        info: Buffer | None = None,
        aad: Buffer | None = None,
    ) -> bytes: ...
