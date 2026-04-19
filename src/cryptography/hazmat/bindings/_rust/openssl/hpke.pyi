# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519
from cryptography.utils import Buffer

class KEM:
    X25519: KEM
    P256: KEM
    P384: KEM
    P521: KEM
    MLKEM768: KEM
    MLKEM1024: KEM

class KDF:
    HKDF_SHA256: KDF
    HKDF_SHA384: KDF
    HKDF_SHA512: KDF
    SHAKE128: KDF
    SHAKE256: KDF

class AEAD:
    AES_128_GCM: AEAD
    AES_256_GCM: AEAD
    CHACHA20_POLY1305: AEAD

class Suite:
    def __init__(self, kem: KEM, kdf: KDF, aead: AEAD) -> None: ...
    def encrypt(
        self,
        plaintext: Buffer,
        public_key: x25519.X25519PublicKey
        | ec.EllipticCurvePublicKey
        | mlkem.MLKEM768PublicKey
        | mlkem.MLKEM1024PublicKey,
        info: Buffer | None = None,
    ) -> bytes: ...
    def decrypt(
        self,
        ciphertext: Buffer,
        private_key: x25519.X25519PrivateKey
        | ec.EllipticCurvePrivateKey
        | mlkem.MLKEM768PrivateKey
        | mlkem.MLKEM1024PrivateKey,
        info: Buffer | None = None,
    ) -> bytes: ...

def _encrypt_with_aad(
    suite: Suite,
    plaintext: Buffer,
    public_key: x25519.X25519PublicKey
    | ec.EllipticCurvePublicKey
    | mlkem.MLKEM768PublicKey
    | mlkem.MLKEM1024PublicKey,
    info: Buffer | None = None,
    aad: Buffer | None = None,
) -> bytes: ...
def _decrypt_with_aad(
    suite: Suite,
    ciphertext: Buffer,
    private_key: x25519.X25519PrivateKey
    | ec.EllipticCurvePrivateKey
    | mlkem.MLKEM768PrivateKey
    | mlkem.MLKEM1024PrivateKey,
    info: Buffer | None = None,
    aad: Buffer | None = None,
) -> bytes: ...
