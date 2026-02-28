# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.utils import Buffer

class KEM:
    X25519: KEM

class KDF:
    HKDF_SHA256: KDF

class AEAD:
    AES_128_GCM: AEAD

class Suite:
    def __init__(self, kem: KEM, kdf: KDF, aead: AEAD) -> None: ...
    def encrypt(
        self,
        plaintext: Buffer,
        public_key: x25519.X25519PublicKey,
        info: Buffer | None = None,
    ) -> bytes: ...
    def decrypt(
        self,
        ciphertext: Buffer,
        private_key: x25519.X25519PrivateKey,
        info: Buffer | None = None,
    ) -> bytes: ...

def _encrypt_with_aad(
    suite: Suite,
    plaintext: Buffer,
    public_key: x25519.X25519PublicKey,
    info: Buffer | None = None,
    aad: Buffer | None = None,
) -> bytes: ...
def _decrypt_with_aad(
    suite: Suite,
    ciphertext: Buffer,
    private_key: x25519.X25519PrivateKey,
    info: Buffer | None = None,
    aad: Buffer | None = None,
) -> bytes: ...
