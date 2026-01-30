# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import json
import os

import pytest

from cryptography.exceptions import InvalidTag
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
]


@pytest.mark.supported(
    only_if=lambda backend: backend.x25519_supported(),
    skip_message="Requires OpenSSL with X25519 support",
)
class TestHPKE:
    def test_invalid_kem_type(self):
        with pytest.raises(TypeError, match="kem must be an instance of KEM"):
            Suite("not a kem", KDF.HKDF_SHA256, AEAD.AES_128_GCM)  # type: ignore[arg-type]

    def test_invalid_kdf_type(self):
        with pytest.raises(TypeError, match="kdf must be an instance of KDF"):
            Suite(KEM.X25519, "not a kdf", AEAD.AES_128_GCM)  # type: ignore[arg-type]

    def test_invalid_aead_type(self):
        with pytest.raises(
            TypeError, match="aead must be an instance of AEAD"
        ):
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

    def test_wrong_aad_fails_internal(self):
        """Test that wrong AAD fails using internal API."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite._encrypt(
            b"Secret message", pk_r, info=b"", aad=b"correct aad"
        )

        with pytest.raises(InvalidTag):
            suite._decrypt(ciphertext, sk_r, info=b"", aad=b"wrong aad")

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

    def test_vector_decryption(self, subtests):
        vectors = load_vectors_from_file(
            os.path.join("HPKE", "test-vectors.json"),
            lambda f: json.load(f),
        )

        for vector in vectors:
            # Currently support: mode 0 (Base), X25519, HKDF-SHA256, AES-GCM
            if not (
                vector["mode"] == 0
                and vector["kem_id"] == 0x0020
                and vector["kdf_id"] == 0x0001
                and vector["aead_id"] == 0x0001
            ):
                continue

            with subtests.test():
                suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

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
                # Use internal API with AAD for test vector validation
                ciphertext = enc + ct
                pt = suite._decrypt(ciphertext, sk_r, info=info, aad=aad)
                assert pt == pt_expected
