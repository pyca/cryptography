# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import hashlib
import itertools
import json
import os

import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519
from cryptography.hazmat.primitives.hpke import (
    AEAD,
    KDF,
    KEM,
    MLKEM768X25519PrivateKey,
    MLKEM768X25519PublicKey,
    MLKEM1024P384PrivateKey,
    MLKEM1024P384PublicKey,
    Suite,
)

from ...utils import load_vectors_from_file


def _hybrid_from_xwing_seed(
    seed: bytes,
) -> MLKEM768X25519PrivateKey:
    # X-Wing seed expansion: SHAKE256(seed, 96) -> (d || z || sk_X).
    expanded = hashlib.shake_256(seed).digest(96)
    mlkem_sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64])
    x25519_sk = x25519.X25519PrivateKey.from_private_bytes(expanded[64:96])
    return MLKEM768X25519PrivateKey(mlkem_sk, x25519_sk)


def _hybrid_from_mlkem1024_p384_seed(
    seed: bytes,
) -> MLKEM1024P384PrivateKey:
    # MLKEM1024-P384 seed expansion: SHAKE256(seed, 112) -> (seed_PQ (64) ||
    # seed_T (48)).
    expanded = hashlib.shake_256(seed).digest(112)
    mlkem_sk = mlkem.MLKEM1024PrivateKey.from_seed_bytes(expanded[:64])
    p384_value = int.from_bytes(expanded[64:112], "big")
    p384_sk = ec.derive_private_key(p384_value, ec.SECP384R1())
    return MLKEM1024P384PrivateKey(mlkem_sk, p384_sk)


X25519_ENC_LENGTH = 32
P256_ENC_LENGTH = 65
P384_ENC_LENGTH = 97
P521_ENC_LENGTH = 133
MLKEM768_ENC_LENGTH = 1088
MLKEM1024_ENC_LENGTH = 1568
MLKEM768_X25519_ENC_LENGTH = 1120
MLKEM1024_P384_ENC_LENGTH = 1665

SUPPORTED_SUITES = list(
    itertools.product(
        [
            KEM.X25519,
            KEM.P256,
            KEM.P384,
            KEM.P521,
            KEM.MLKEM768,
            KEM.MLKEM1024,
            KEM.MLKEM768_X25519,
            KEM.MLKEM1024_P384,
        ],
        [
            KDF.HKDF_SHA256,
            KDF.HKDF_SHA384,
            KDF.HKDF_SHA512,
            KDF.SHAKE128,
            KDF.SHAKE256,
        ],
        [AEAD.AES_128_GCM, AEAD.AES_256_GCM, AEAD.CHACHA20_POLY1305],
    )
)


@pytest.mark.supported(
    only_if=lambda backend: backend.x25519_supported(),
    skip_message="Requires OpenSSL with X25519 support",
)
class TestHPKE:
    def test_invalid_kem_type(self):
        with pytest.raises(TypeError):
            Suite("not a kem", KDF.HKDF_SHA256, AEAD.AES_128_GCM)  # type: ignore[arg-type]

    def test_invalid_kdf_type(self):
        with pytest.raises(TypeError):
            Suite(KEM.X25519, "not a kdf", AEAD.AES_128_GCM)  # type: ignore[arg-type]

    def test_invalid_aead_type(self):
        with pytest.raises(TypeError):
            Suite(KEM.X25519, KDF.HKDF_SHA256, "not an aead")  # type: ignore[arg-type]

    @pytest.mark.parametrize("kem,kdf,aead", SUPPORTED_SUITES)
    def test_roundtrip(self, backend, kem, kdf, aead):
        if kdf == KDF.SHAKE128 and not backend.hash_supported(
            hashes.SHAKE128(digest_size=32)
        ):
            pytest.skip("SHAKE128 not supported")
        if kdf == KDF.SHAKE256 and not backend.hash_supported(
            hashes.SHAKE256(digest_size=64)
        ):
            pytest.skip("SHAKE256 not supported")
        if (
            kem
            in [
                KEM.MLKEM768,
                KEM.MLKEM1024,
                KEM.MLKEM768_X25519,
                KEM.MLKEM1024_P384,
            ]
            and not backend.mlkem_supported()
        ):
            pytest.skip("ML-KEM not supported")
        if kem in [
            KEM.MLKEM768_X25519,
            KEM.MLKEM1024_P384,
        ] and not backend.hash_supported(hashes.SHA3_256()):
            pytest.skip("SHA3-256 not supported")
        suite = Suite(kem, kdf, aead)

        sk_r: (
            x25519.X25519PrivateKey
            | ec.EllipticCurvePrivateKey
            | mlkem.MLKEM768PrivateKey
            | mlkem.MLKEM1024PrivateKey
            | MLKEM768X25519PrivateKey
            | MLKEM1024P384PrivateKey
        )
        if kem == KEM.X25519:
            sk_r = x25519.X25519PrivateKey.generate()
        elif kem == KEM.P256:
            sk_r = ec.generate_private_key(ec.SECP256R1())
        elif kem == KEM.P384:
            sk_r = ec.generate_private_key(ec.SECP384R1())
        elif kem == KEM.P521:
            sk_r = ec.generate_private_key(ec.SECP521R1())
        elif kem == KEM.MLKEM768:
            sk_r = mlkem.MLKEM768PrivateKey.generate()
        elif kem == KEM.MLKEM1024:
            sk_r = mlkem.MLKEM1024PrivateKey.generate()
        elif kem == KEM.MLKEM768_X25519:
            sk_r = MLKEM768X25519PrivateKey(
                mlkem.MLKEM768PrivateKey.generate(),
                x25519.X25519PrivateKey.generate(),
            )
        else:
            sk_r = MLKEM1024P384PrivateKey(
                mlkem.MLKEM1024PrivateKey.generate(),
                ec.generate_private_key(ec.SECP384R1()),
            )
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"Hello, HPKE!", pk_r, info=b"test")
        plaintext = suite.decrypt(ciphertext, sk_r, info=b"test")

        assert plaintext == b"Hello, HPKE!"

    @pytest.mark.parametrize("kem,kdf,aead", SUPPORTED_SUITES)
    def test_roundtrip_no_info(self, backend, kem, kdf, aead):
        if kdf == KDF.SHAKE128 and not backend.hash_supported(
            hashes.SHAKE128(digest_size=32)
        ):
            pytest.skip("SHAKE128 not supported")
        if kdf == KDF.SHAKE256 and not backend.hash_supported(
            hashes.SHAKE256(digest_size=64)
        ):
            pytest.skip("SHAKE256 not supported")
        if (
            kem
            in [
                KEM.MLKEM768,
                KEM.MLKEM1024,
                KEM.MLKEM768_X25519,
                KEM.MLKEM1024_P384,
            ]
            and not backend.mlkem_supported()
        ):
            pytest.skip("ML-KEM not supported")
        if kem in [
            KEM.MLKEM768_X25519,
            KEM.MLKEM1024_P384,
        ] and not backend.hash_supported(hashes.SHA3_256()):
            pytest.skip("SHA3-256 not supported")
        suite = Suite(kem, kdf, aead)

        sk_r: (
            x25519.X25519PrivateKey
            | ec.EllipticCurvePrivateKey
            | mlkem.MLKEM768PrivateKey
            | mlkem.MLKEM1024PrivateKey
            | MLKEM768X25519PrivateKey
            | MLKEM1024P384PrivateKey
        )
        if kem == KEM.X25519:
            sk_r = x25519.X25519PrivateKey.generate()
        elif kem == KEM.P256:
            sk_r = ec.generate_private_key(ec.SECP256R1())
        elif kem == KEM.P384:
            sk_r = ec.generate_private_key(ec.SECP384R1())
        elif kem == KEM.P521:
            sk_r = ec.generate_private_key(ec.SECP521R1())
        elif kem == KEM.MLKEM768:
            sk_r = mlkem.MLKEM768PrivateKey.generate()
        elif kem == KEM.MLKEM1024:
            sk_r = mlkem.MLKEM1024PrivateKey.generate()
        elif kem == KEM.MLKEM768_X25519:
            sk_r = MLKEM768X25519PrivateKey(
                mlkem.MLKEM768PrivateKey.generate(),
                x25519.X25519PrivateKey.generate(),
            )
        else:
            sk_r = MLKEM1024P384PrivateKey(
                mlkem.MLKEM1024PrivateKey.generate(),
                ec.generate_private_key(ec.SECP384R1()),
            )
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"Hello!", pk_r)
        plaintext = suite.decrypt(ciphertext, sk_r)

        assert plaintext == b"Hello!"

    def test_wrong_key_x25519(self):
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()
        ciphertext = suite.encrypt(b"test", pk_r)

        # Wrong key of correct type
        sk_wrong = x25519.X25519PrivateKey.generate()
        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_wrong)

        # Wrong key type for encrypt
        ec_pk = ec.generate_private_key(ec.SECP256R1()).public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", ec_pk)

        # Wrong key type for decrypt
        ec_sk = ec.generate_private_key(ec.SECP256R1())
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, ec_sk)

    def test_wrong_key_p256(self):
        suite = Suite(KEM.P256, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        sk_r = ec.generate_private_key(ec.SECP256R1())
        pk_r = sk_r.public_key()
        ciphertext = suite.encrypt(b"test", pk_r)

        # Wrong key of correct type
        sk_wrong = ec.generate_private_key(ec.SECP256R1())
        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_wrong)

        # Wrong key type for encrypt
        x25519_pk = x25519.X25519PrivateKey.generate().public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", x25519_pk)

        # Wrong key type for decrypt
        x25519_sk = x25519.X25519PrivateKey.generate()
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, x25519_sk)

        # Wrong EC curve for encrypt
        secp384r1_pk = ec.generate_private_key(ec.SECP384R1()).public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", secp384r1_pk)

        # Wrong EC curve for decrypt
        secp384r1_sk = ec.generate_private_key(ec.SECP384R1())
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, secp384r1_sk)

    def test_wrong_key_p384(self):
        suite = Suite(KEM.P384, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        sk_r = ec.generate_private_key(ec.SECP384R1())
        pk_r = sk_r.public_key()
        ciphertext = suite.encrypt(b"test", pk_r)

        # Wrong key of correct type
        sk_wrong = ec.generate_private_key(ec.SECP384R1())
        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_wrong)

        # Wrong key type for encrypt
        x25519_pk = x25519.X25519PrivateKey.generate().public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", x25519_pk)

        # Wrong key type for decrypt
        x25519_sk = x25519.X25519PrivateKey.generate()
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, x25519_sk)

        # Wrong EC curve for encrypt
        secp256r1_pk = ec.generate_private_key(ec.SECP256R1()).public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", secp256r1_pk)

        # Wrong EC curve for decrypt
        secp256r1_sk = ec.generate_private_key(ec.SECP256R1())
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, secp256r1_sk)

        # Wrong EC curve (P-521) for encrypt
        secp521r1_pk = ec.generate_private_key(ec.SECP521R1()).public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", secp521r1_pk)

        # Wrong EC curve (P-521) for decrypt
        secp521r1_sk = ec.generate_private_key(ec.SECP521R1())
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, secp521r1_sk)

    def test_wrong_key_p521(self):
        suite = Suite(KEM.P521, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        sk_r = ec.generate_private_key(ec.SECP521R1())
        pk_r = sk_r.public_key()
        ciphertext = suite.encrypt(b"test", pk_r)

        # Wrong key of correct type
        sk_wrong = ec.generate_private_key(ec.SECP521R1())
        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_wrong)

        # Wrong key type for encrypt
        x25519_pk = x25519.X25519PrivateKey.generate().public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", x25519_pk)

        # Wrong key type for decrypt
        x25519_sk = x25519.X25519PrivateKey.generate()
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, x25519_sk)

        # Wrong EC curve for encrypt
        secp256r1_pk = ec.generate_private_key(ec.SECP256R1()).public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", secp256r1_pk)

        # Wrong EC curve for decrypt
        secp256r1_sk = ec.generate_private_key(ec.SECP256R1())
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, secp256r1_sk)

        # Wrong EC curve (P-384) for encrypt
        secp384r1_pk = ec.generate_private_key(ec.SECP384R1()).public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", secp384r1_pk)

        # Wrong EC curve (P-384) for decrypt
        secp384r1_sk = ec.generate_private_key(ec.SECP384R1())
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, secp384r1_sk)

    def test_wrong_aad_fails(self):
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = rust_openssl.hpke._encrypt_with_aad(
            suite, b"Secret message", pk_r, aad=b"correct aad"
        )

        with pytest.raises(InvalidTag):
            rust_openssl.hpke._decrypt_with_aad(
                suite, ciphertext, sk_r, aad=b"wrong aad"
            )

    def test_info_mismatch_fails(self):
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"Secret", pk_r, info=b"sender info")

        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_r, info=b"different info")

    def test_ciphertext_format(self):
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        # ciphertext should be: enc (32 bytes) + ct (4 bytes pt + 16 bytes tag)
        assert len(ciphertext) == X25519_ENC_LENGTH + 4 + 16

    def test_ciphertext_format_p256(self):
        suite = Suite(KEM.P256, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = ec.generate_private_key(ec.SECP256R1())
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        # ciphertext should be: enc (65 bytes) + ct (4 bytes pt + 16 bytes tag)
        assert len(ciphertext) == P256_ENC_LENGTH + 4 + 16

    def test_ciphertext_format_p384(self):
        suite = Suite(KEM.P384, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = ec.generate_private_key(ec.SECP384R1())
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        # enc (97 bytes) + ct (4 bytes pt + 16 bytes tag)
        assert len(ciphertext) == P384_ENC_LENGTH + 4 + 16

    def test_ciphertext_format_p521(self):
        suite = Suite(KEM.P521, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = ec.generate_private_key(ec.SECP521R1())
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        # enc (133 bytes) + ct (4 bytes pt + 16 bytes tag)
        assert len(ciphertext) == P521_ENC_LENGTH + 4 + 16

    @pytest.mark.supported(
        only_if=lambda backend: backend.mlkem_supported(),
        skip_message="Requires ML-KEM support",
    )
    def test_ciphertext_format_mlkem768(self):
        suite = Suite(KEM.MLKEM768, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = mlkem.MLKEM768PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        # enc (1088 bytes) + ct (4 bytes pt + 16 bytes tag)
        assert len(ciphertext) == MLKEM768_ENC_LENGTH + 4 + 16

    @pytest.mark.supported(
        only_if=lambda backend: backend.mlkem_supported(),
        skip_message="Requires ML-KEM support",
    )
    def test_wrong_key_mlkem768(self):
        suite = Suite(KEM.MLKEM768, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        sk_r = mlkem.MLKEM768PrivateKey.generate()
        pk_r = sk_r.public_key()
        ciphertext = suite.encrypt(b"test", pk_r)

        # Wrong key of correct type
        sk_wrong = mlkem.MLKEM768PrivateKey.generate()
        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_wrong)

        # Wrong key type for encrypt
        x25519_pk = x25519.X25519PrivateKey.generate().public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", x25519_pk)

        # Wrong key type for decrypt
        x25519_sk = x25519.X25519PrivateKey.generate()
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, x25519_sk)

    @pytest.mark.supported(
        only_if=lambda backend: backend.mlkem_supported(),
        skip_message="Requires ML-KEM support",
    )
    def test_mlkem768_wrong_kem_with_ec(self):
        # ML-KEM public key with EC-based KEM suite should fail
        suite = Suite(KEM.P256, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        mlkem_pk = mlkem.MLKEM768PrivateKey.generate().public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", mlkem_pk)

    @pytest.mark.supported(
        only_if=lambda backend: backend.mlkem_supported(),
        skip_message="Requires ML-KEM support",
    )
    def test_ciphertext_format_mlkem1024(self):
        suite = Suite(KEM.MLKEM1024, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = mlkem.MLKEM1024PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        # enc (1568 bytes) + ct (4 bytes pt + 16 bytes tag)
        assert len(ciphertext) == MLKEM1024_ENC_LENGTH + 4 + 16

    @pytest.mark.supported(
        only_if=lambda backend: backend.mlkem_supported(),
        skip_message="Requires ML-KEM support",
    )
    def test_wrong_key_mlkem1024(self):
        suite = Suite(KEM.MLKEM1024, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        sk_r = mlkem.MLKEM1024PrivateKey.generate()
        pk_r = sk_r.public_key()
        ciphertext = suite.encrypt(b"test", pk_r)

        # Wrong key of correct type
        sk_wrong = mlkem.MLKEM1024PrivateKey.generate()
        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_wrong)

        # Wrong key type for encrypt
        x25519_pk = x25519.X25519PrivateKey.generate().public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", x25519_pk)

        # Wrong key type for decrypt
        x25519_sk = x25519.X25519PrivateKey.generate()
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, x25519_sk)

        # ML-KEM-768 key with ML-KEM-1024 suite should fail
        mlkem768_pk = mlkem.MLKEM768PrivateKey.generate().public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", mlkem768_pk)

        mlkem768_sk = mlkem.MLKEM768PrivateKey.generate()
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, mlkem768_sk)

    @pytest.mark.supported(
        only_if=lambda backend: backend.mlkem_supported(),
        skip_message="Requires ML-KEM support",
    )
    def test_mlkem1024_wrong_kem_with_ec(self):
        # ML-KEM-1024 public key with EC-based KEM suite should fail
        suite = Suite(KEM.P256, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        mlkem_pk = mlkem.MLKEM1024PrivateKey.generate().public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", mlkem_pk)

    @pytest.mark.supported(
        only_if=lambda backend: (
            backend.mlkem_supported()
            and backend.hash_supported(hashes.SHA3_256())
        ),
        skip_message="Requires ML-KEM and SHA3-256 support",
    )
    def test_ciphertext_format_mlkem768_x25519(self):
        suite = Suite(KEM.MLKEM768_X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        mlkem_sk = mlkem.MLKEM768PrivateKey.generate()
        x25519_sk = x25519.X25519PrivateKey.generate()
        pk_r = MLKEM768X25519PublicKey(
            mlkem_sk.public_key(), x25519_sk.public_key()
        )

        ciphertext = suite.encrypt(b"test", pk_r)

        # enc (1120 bytes) + ct (4 bytes pt + 16 bytes tag)
        assert len(ciphertext) == MLKEM768_X25519_ENC_LENGTH + 4 + 16

    @pytest.mark.supported(
        only_if=lambda backend: (
            backend.mlkem_supported()
            and backend.hash_supported(hashes.SHA3_256())
        ),
        skip_message="Requires ML-KEM and SHA3-256 support",
    )
    def test_wrong_key_mlkem768_x25519(self):
        suite = Suite(KEM.MLKEM768_X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        mlkem_sk = mlkem.MLKEM768PrivateKey.generate()
        x25519_sk = x25519.X25519PrivateKey.generate()
        sk_r = MLKEM768X25519PrivateKey(mlkem_sk, x25519_sk)
        pk_r = MLKEM768X25519PublicKey(
            mlkem_sk.public_key(), x25519_sk.public_key()
        )
        ciphertext = suite.encrypt(b"test", pk_r)
        # Correct key decrypts successfully.
        assert suite.decrypt(ciphertext, sk_r) == b"test"

        # Wrong key of correct type
        sk_wrong = MLKEM768X25519PrivateKey(
            mlkem.MLKEM768PrivateKey.generate(),
            x25519.X25519PrivateKey.generate(),
        )
        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_wrong)

        # Wrong key type for encrypt
        stray_x25519_pk = x25519.X25519PrivateKey.generate().public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", stray_x25519_pk)

        # Wrong key type for decrypt
        stray_x25519_sk = x25519.X25519PrivateKey.generate()
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, stray_x25519_sk)

        # ML-KEM-768 key with hybrid suite should fail
        mlkem768_pk = mlkem.MLKEM768PrivateKey.generate().public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", mlkem768_pk)

        mlkem768_sk = mlkem.MLKEM768PrivateKey.generate()
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, mlkem768_sk)

    @pytest.mark.supported(
        only_if=lambda backend: backend.mlkem_supported(),
        skip_message="Requires ML-KEM support",
    )
    def test_mlkem768_x25519_wrong_kem_with_ec(self):
        # Hybrid public key with EC-based KEM suite should fail
        suite = Suite(KEM.P256, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        mlkem_sk = mlkem.MLKEM768PrivateKey.generate()
        x25519_sk = x25519.X25519PrivateKey.generate()
        hybrid_pk = MLKEM768X25519PublicKey(
            mlkem_sk.public_key(), x25519_sk.public_key()
        )
        with pytest.raises(TypeError):
            suite.encrypt(b"test", hybrid_pk)

    @pytest.mark.supported(
        only_if=lambda backend: backend.mlkem_supported(),
        skip_message="Requires ML-KEM support",
    )
    def test_mlkem768_x25519_constructor_type_errors(self):
        mlkem_sk = mlkem.MLKEM768PrivateKey.generate()
        mlkem_pk = mlkem_sk.public_key()
        x25519_sk = x25519.X25519PrivateKey.generate()
        x25519_pk = x25519_sk.public_key()

        # Wrong type for mlkem_key in private constructor.
        with pytest.raises(TypeError):
            MLKEM768X25519PrivateKey(x25519_sk, x25519_sk)  # type: ignore[arg-type]
        # Wrong type for x25519_key in private constructor.
        with pytest.raises(TypeError):
            MLKEM768X25519PrivateKey(mlkem_sk, mlkem_sk)  # type: ignore[arg-type]

        # Wrong type for mlkem_key in public constructor.
        with pytest.raises(TypeError):
            MLKEM768X25519PublicKey(x25519_pk, x25519_pk)  # type: ignore[arg-type]
        # Wrong type for x25519_key in public constructor.
        with pytest.raises(TypeError):
            MLKEM768X25519PublicKey(mlkem_pk, mlkem_pk)  # type: ignore[arg-type]

    @pytest.mark.supported(
        only_if=lambda backend: (
            backend.mlkem_supported()
            and backend.hash_supported(hashes.SHA3_256())
        ),
        skip_message="Requires ML-KEM and SHA3-256 support",
    )
    def test_ciphertext_format_mlkem1024_p384(self):
        suite = Suite(KEM.MLKEM1024_P384, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        mlkem_sk = mlkem.MLKEM1024PrivateKey.generate()
        p384_sk = ec.generate_private_key(ec.SECP384R1())
        pk_r = MLKEM1024P384PublicKey(
            mlkem_sk.public_key(), p384_sk.public_key()
        )

        ciphertext = suite.encrypt(b"test", pk_r)

        # enc (1665 bytes) + ct (4 bytes pt + 16 bytes tag)
        assert len(ciphertext) == MLKEM1024_P384_ENC_LENGTH + 4 + 16

    @pytest.mark.supported(
        only_if=lambda backend: (
            backend.mlkem_supported()
            and backend.hash_supported(hashes.SHA3_256())
        ),
        skip_message="Requires ML-KEM and SHA3-256 support",
    )
    def test_wrong_key_mlkem1024_p384(self):
        suite = Suite(KEM.MLKEM1024_P384, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        mlkem_sk = mlkem.MLKEM1024PrivateKey.generate()
        p384_sk = ec.generate_private_key(ec.SECP384R1())
        sk_r = MLKEM1024P384PrivateKey(mlkem_sk, p384_sk)
        pk_r = MLKEM1024P384PublicKey(
            mlkem_sk.public_key(), p384_sk.public_key()
        )
        ciphertext = suite.encrypt(b"test", pk_r)
        # Correct key decrypts successfully.
        assert suite.decrypt(ciphertext, sk_r) == b"test"

        # Wrong key of correct type
        sk_wrong = MLKEM1024P384PrivateKey(
            mlkem.MLKEM1024PrivateKey.generate(),
            ec.generate_private_key(ec.SECP384R1()),
        )
        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_wrong)

        # Wrong key type for encrypt
        stray_p384_pk = ec.generate_private_key(ec.SECP384R1()).public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", stray_p384_pk)

        # Wrong key type for decrypt
        stray_p384_sk = ec.generate_private_key(ec.SECP384R1())
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, stray_p384_sk)

        # ML-KEM-1024 key with hybrid suite should fail
        mlkem1024_pk = mlkem.MLKEM1024PrivateKey.generate().public_key()
        with pytest.raises(TypeError):
            suite.encrypt(b"test", mlkem1024_pk)

        mlkem1024_sk = mlkem.MLKEM1024PrivateKey.generate()
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, mlkem1024_sk)

    @pytest.mark.supported(
        only_if=lambda backend: backend.mlkem_supported(),
        skip_message="Requires ML-KEM support",
    )
    def test_mlkem1024_p384_wrong_kem_with_ec(self):
        # Hybrid public key with EC-based KEM suite should fail
        suite = Suite(KEM.P256, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        mlkem_sk = mlkem.MLKEM1024PrivateKey.generate()
        p384_sk = ec.generate_private_key(ec.SECP384R1())
        hybrid_pk = MLKEM1024P384PublicKey(
            mlkem_sk.public_key(), p384_sk.public_key()
        )
        with pytest.raises(TypeError):
            suite.encrypt(b"test", hybrid_pk)

    @pytest.mark.supported(
        only_if=lambda backend: backend.mlkem_supported(),
        skip_message="Requires ML-KEM support",
    )
    def test_mlkem1024_p384_constructor_type_errors(self):
        mlkem_sk = mlkem.MLKEM1024PrivateKey.generate()
        mlkem_pk = mlkem_sk.public_key()
        p384_sk = ec.generate_private_key(ec.SECP384R1())
        p384_pk = p384_sk.public_key()
        # Wrong-curve EC keys for curve validation paths.
        p256_sk = ec.generate_private_key(ec.SECP256R1())
        p256_pk = p256_sk.public_key()

        # Wrong type for mlkem_key in private constructor.
        with pytest.raises(TypeError):
            MLKEM1024P384PrivateKey(p384_sk, p384_sk)  # type: ignore[arg-type]
        # Wrong type for p384_key in private constructor.
        with pytest.raises(TypeError):
            MLKEM1024P384PrivateKey(mlkem_sk, mlkem_sk)  # type: ignore[arg-type]
        # Wrong EC curve for p384_key in private constructor.
        with pytest.raises(TypeError):
            MLKEM1024P384PrivateKey(mlkem_sk, p256_sk)

        # Wrong type for mlkem_key in public constructor.
        with pytest.raises(TypeError):
            MLKEM1024P384PublicKey(p384_pk, p384_pk)  # type: ignore[arg-type]
        # Wrong type for p384_key in public constructor.
        with pytest.raises(TypeError):
            MLKEM1024P384PublicKey(mlkem_pk, mlkem_pk)  # type: ignore[arg-type]
        # Wrong EC curve for p384_key in public constructor.
        with pytest.raises(TypeError):
            MLKEM1024P384PublicKey(mlkem_pk, p256_pk)

    def test_empty_plaintext(self):
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"", pk_r)
        plaintext = suite.decrypt(ciphertext, sk_r)

        assert plaintext == b""

    def test_large_plaintext(self):
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        large_message = b"A" * 100000

        ciphertext = suite.encrypt(large_message, pk_r)
        plaintext = suite.decrypt(ciphertext, sk_r)

        assert plaintext == large_message

    def test_corrupted_ciphertext(self):
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        # Corrupt the ciphertext (after enc)
        corrupted = (
            ciphertext[:X25519_ENC_LENGTH]
            + bytes([ciphertext[X25519_ENC_LENGTH] ^ 0xFF])
            + ciphertext[X25519_ENC_LENGTH + 1 :]
        )

        with pytest.raises(InvalidTag):
            suite.decrypt(corrupted, sk_r)

    def test_truncated_ciphertext(self):
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        # Truncate the ciphertext
        truncated = ciphertext[:-1]

        with pytest.raises(InvalidTag):
            suite.decrypt(truncated, sk_r)
        with pytest.raises(InvalidTag):
            suite.decrypt(b"\x00", sk_r)

    @pytest.mark.parametrize(
        "small_order_point",
        [
            # All 8 known small-order points on Curve25519
            bytes(32),  # Zero point (order 1)
            bytes([1] + [0] * 31),  # Order 4
            bytes.fromhex(
                "ecffffffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffff7f"
            ),  # Order 8
            bytes.fromhex(
                "5f9c95bca3508c24b1d0b1559c83ef5b04445cc"
                "4581c8e86d8224eddd09f1157"
            ),  # Order 8
            bytes.fromhex(
                "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb"
                "9c32b1fd866205165f49b800"
            ),  # Order 2
            bytes.fromhex(
                "0000000000000000000000000000000000000000"
                "000000000000000000000080"
            ),  # p (order 1)
            bytes.fromhex(
                "0100000000000000000000000000000000000000"
                "000000000000000000000080"
            ),  # p+1 (order 4)
            bytes.fromhex(
                "edffffffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffff"
            ),  # p-1 (order 1)
        ],
    )
    def test_small_order_enc_raises_invalid_tag(self, small_order_point):
        """Small-order X25519 enc points must raise InvalidTag,
        not ValueError, to avoid leaking an error oracle."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        sk_r = x25519.X25519PrivateKey.generate()

        # Build a fake ciphertext: small-order enc (32 bytes) + fake ct
        fake_ciphertext = small_order_point + b"\x00" * 32

        with pytest.raises(InvalidTag):
            suite.decrypt(fake_ciphertext, sk_r)

    def test_invalid_p256_enc_raises_invalid_tag(self):
        """Invalid P-256 enc points must raise InvalidTag."""
        suite = Suite(KEM.P256, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        sk_r = ec.generate_private_key(ec.SECP256R1())

        # Build a fake ciphertext: invalid enc (65 bytes) + fake ct
        fake_ciphertext = b"\x04" + b"\x00" * 64 + b"\x00" * 32

        with pytest.raises(InvalidTag):
            suite.decrypt(fake_ciphertext, sk_r)

    def test_info_too_large_fails_shake128(self, backend):
        if not backend.hash_supported(hashes.SHAKE128(digest_size=32)):
            pytest.skip("SHAKE128 not supported")
        suite = Suite(KEM.X25519, KDF.SHAKE128, AEAD.AES_128_GCM)
        pk_r = x25519.X25519PrivateKey.generate().public_key()

        with pytest.raises(ValueError, match="info is too large"):
            suite.encrypt(b"test", pk_r, info=b"x" * 65536)

    def test_info_too_large_fails_shake256(self, backend):
        if not backend.hash_supported(hashes.SHAKE256(digest_size=64)):
            pytest.skip("SHAKE256 not supported")
        suite = Suite(KEM.X25519, KDF.SHAKE256, AEAD.AES_128_GCM)
        pk_r = x25519.X25519PrivateKey.generate().public_key()

        with pytest.raises(ValueError, match="info is too large"):
            suite.encrypt(b"test", pk_r, info=b"x" * 65536)

    def test_vector_decryption(self, backend, subtests):
        rfc_vectors = load_vectors_from_file(
            os.path.join("HPKE", "test-vectors.json"),
            lambda f: json.load(f),
        )
        pq_vectors = load_vectors_from_file(
            os.path.join("HPKE", "hpke-pq-test-vectors.json"),
            lambda f: json.load(f),
        )

        kem_map = {
            0x0010: KEM.P256,
            0x0011: KEM.P384,
            0x0012: KEM.P521,
            0x0020: KEM.X25519,
            0x0041: KEM.MLKEM768,
            0x0042: KEM.MLKEM1024,
            0x0051: KEM.MLKEM1024_P384,
            0x647A: KEM.MLKEM768_X25519,
        }
        kdf_map = {
            0x0001: KDF.HKDF_SHA256,
            0x0002: KDF.HKDF_SHA384,
            0x0003: KDF.HKDF_SHA512,
            0x0010: KDF.SHAKE128,
            0x0011: KDF.SHAKE256,
        }
        aead_map = {
            0x0001: AEAD.AES_128_GCM,
            0x0002: AEAD.AES_256_GCM,
            0x0003: AEAD.CHACHA20_POLY1305,
        }

        for vector in rfc_vectors + pq_vectors:
            if not (
                vector["mode"] == 0
                and vector["kem_id"] in kem_map
                and vector["kdf_id"] in kdf_map
                and vector["aead_id"] in aead_map
            ):
                continue

            with subtests.test():
                kem = kem_map[vector["kem_id"]]
                kdf = kdf_map[vector["kdf_id"]]
                aead = aead_map[vector["aead_id"]]

                if kdf == KDF.SHAKE128 and not backend.hash_supported(
                    hashes.SHAKE128(digest_size=32)
                ):
                    continue
                if kdf == KDF.SHAKE256 and not backend.hash_supported(
                    hashes.SHAKE256(digest_size=64)
                ):
                    continue
                if (
                    kem
                    in [
                        KEM.MLKEM768,
                        KEM.MLKEM1024,
                        KEM.MLKEM768_X25519,
                        KEM.MLKEM1024_P384,
                    ]
                    and not backend.mlkem_supported()
                ):
                    continue
                if kem in [
                    KEM.MLKEM768_X25519,
                    KEM.MLKEM1024_P384,
                ] and not backend.hash_supported(hashes.SHA3_256()):
                    continue

                suite = Suite(kem, kdf, aead)

                sk_r_bytes = bytes.fromhex(vector["skRm"])
                sk_r: (
                    x25519.X25519PrivateKey
                    | ec.EllipticCurvePrivateKey
                    | mlkem.MLKEM768PrivateKey
                    | mlkem.MLKEM1024PrivateKey
                    | MLKEM768X25519PrivateKey
                    | MLKEM1024P384PrivateKey
                )
                if kem == KEM.X25519:
                    sk_r = x25519.X25519PrivateKey.from_private_bytes(
                        sk_r_bytes
                    )
                elif kem == KEM.P256:
                    private_value = int.from_bytes(sk_r_bytes, "big")
                    sk_r = ec.derive_private_key(private_value, ec.SECP256R1())
                elif kem == KEM.P384:
                    private_value = int.from_bytes(sk_r_bytes, "big")
                    sk_r = ec.derive_private_key(private_value, ec.SECP384R1())
                elif kem == KEM.P521:
                    private_value = int.from_bytes(sk_r_bytes, "big")
                    sk_r = ec.derive_private_key(private_value, ec.SECP521R1())
                elif kem == KEM.MLKEM768:
                    sk_r = mlkem.MLKEM768PrivateKey.from_seed_bytes(sk_r_bytes)
                elif kem == KEM.MLKEM1024:
                    sk_r = mlkem.MLKEM1024PrivateKey.from_seed_bytes(
                        sk_r_bytes
                    )
                elif kem == KEM.MLKEM768_X25519:
                    sk_r = _hybrid_from_xwing_seed(sk_r_bytes)
                else:
                    sk_r = _hybrid_from_mlkem1024_p384_seed(sk_r_bytes)

                enc = bytes.fromhex(vector["enc"])
                info = bytes.fromhex(vector["info"])

                # Test first encryption only (single-shot API)
                encryption = vector["encryptions"][0]
                aad = bytes.fromhex(encryption["aad"])
                ct = bytes.fromhex(encryption["ct"])
                pt_expected = bytes.fromhex(encryption["pt"])

                # Combine enc || ct for single-shot decrypt
                # Use internal function with AAD for test vector
                # validation
                ciphertext = enc + ct
                pt = rust_openssl.hpke._decrypt_with_aad(
                    suite, ciphertext, sk_r, info=info, aad=aad
                )
                assert pt == pt_expected
