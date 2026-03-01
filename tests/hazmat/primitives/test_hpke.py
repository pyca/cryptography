# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import json
import os

import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hpke import (
    AEAD,
    KDF,
    KEM,
    Suite,
)

from ...utils import load_vectors_from_file

X25519_ENC_LENGTH = 32

SUPPORTED_SUITES = [
    (KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM),
    (KEM.X25519, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305),
]


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
    def test_roundtrip(self, kem, kdf, aead):
        suite = Suite(kem, kdf, aead)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"Hello, HPKE!", pk_r, info=b"test")
        plaintext = suite.decrypt(ciphertext, sk_r, info=b"test")

        assert plaintext == b"Hello, HPKE!"

    @pytest.mark.parametrize("kem,kdf,aead", SUPPORTED_SUITES)
    def test_roundtrip_no_info(self, kem, kdf, aead):
        suite = Suite(kem, kdf, aead)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"Hello!", pk_r)
        plaintext = suite.decrypt(ciphertext, sk_r)

        assert plaintext == b"Hello!"

    def test_wrong_key_fails(self):
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()
        sk_wrong = x25519.X25519PrivateKey.generate()

        ciphertext = suite.encrypt(b"Secret message", pk_r)

        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_wrong)

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

    def test_vector_decryption(self, subtests):
        vectors = load_vectors_from_file(
            os.path.join("HPKE", "test-vectors.json"),
            lambda f: json.load(f),
        )

        aead_map = {
            0x0001: AEAD.AES_128_GCM,
            0x0003: AEAD.CHACHA20_POLY1305,
        }

        for vector in vectors:
            # Support: mode 0 (Base), X25519, HKDF-SHA256,
            # AES-128-GCM or ChaCha20Poly1305
            if not (
                vector["mode"] == 0
                and vector["kem_id"] == 0x0020
                and vector["kdf_id"] == 0x0001
                and vector["aead_id"] in aead_map
            ):
                continue

            with subtests.test():
                aead = aead_map[vector["aead_id"]]
                suite = Suite(KEM.X25519, KDF.HKDF_SHA256, aead)

                sk_r_bytes = bytes.fromhex(vector["skRm"])
                sk_r = x25519.X25519PrivateKey.from_private_bytes(sk_r_bytes)
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
