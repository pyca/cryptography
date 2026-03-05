# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import itertools
import json
import os

import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.hpke import (
    AEAD,
    KDF,
    KEM,
    Suite,
)

from ...utils import load_vectors_from_file

HPKEPrivateKey = x25519.X25519PrivateKey | ec.EllipticCurvePrivateKey
HPKEPublicKey = x25519.X25519PublicKey | ec.EllipticCurvePublicKey

ENC_LENGTHS = {
    KEM.X25519: 32,
    KEM.P256: 65,
    KEM.P384: 97,
    KEM.P521: 133,
}

ALL_KEMS = [KEM.X25519, KEM.P256, KEM.P384, KEM.P521]
ALL_KDFS = [KDF.HKDF_SHA256, KDF.HKDF_SHA384, KDF.HKDF_SHA512]

SUPPORTED_SUITES = list(
    itertools.product(
        ALL_KEMS,
        ALL_KDFS,
        [AEAD.AES_128_GCM, AEAD.AES_256_GCM, AEAD.CHACHA20_POLY1305],
    )
)


def _curve_for_kem(kem: KEM) -> ec.EllipticCurve | None:
    if kem == KEM.P256:
        return ec.SECP256R1()
    if kem == KEM.P384:
        return ec.SECP384R1()
    if kem == KEM.P521:
        return ec.SECP521R1()
    return None


def _skip_kem_if_unsupported(backend, kem: KEM) -> None:
    curve = _curve_for_kem(kem)
    if curve is not None and not backend.elliptic_curve_supported(curve):
        pytest.skip(f"Backend does not support {curve.name}")


def _generate_private_key_for_kem(backend, kem: KEM) -> HPKEPrivateKey:
    _skip_kem_if_unsupported(backend, kem)
    if kem == KEM.X25519:
        return x25519.X25519PrivateKey.generate()
    curve = _curve_for_kem(kem)
    assert curve is not None
    return ec.generate_private_key(curve)


def _derive_private_key_for_kem(
    backend, kem: KEM, key_bytes: bytes
) -> HPKEPrivateKey:
    _skip_kem_if_unsupported(backend, kem)
    if kem == KEM.X25519:
        return x25519.X25519PrivateKey.from_private_bytes(key_bytes)
    curve = _curve_for_kem(kem)
    assert curve is not None
    return ec.derive_private_key(int.from_bytes(key_bytes, "big"), curve)


def _other_ec_curve(backend, kem: KEM) -> ec.EllipticCurve | None:
    for other_kem in (KEM.P256, KEM.P384, KEM.P521):
        if other_kem == kem:
            continue
        curve = _curve_for_kem(other_kem)
        assert curve is not None
        if backend.elliptic_curve_supported(curve):
            return curve
    return None


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
    def test_roundtrip(self, kem, kdf, aead, backend):
        suite = Suite(kem, kdf, aead)

        sk_r = _generate_private_key_for_kem(backend, kem)
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"Hello, HPKE!", pk_r, info=b"test")
        plaintext = suite.decrypt(ciphertext, sk_r, info=b"test")

        assert plaintext == b"Hello, HPKE!"

    @pytest.mark.parametrize("kem,kdf,aead", SUPPORTED_SUITES)
    def test_roundtrip_no_info(self, kem, kdf, aead, backend):
        suite = Suite(kem, kdf, aead)

        sk_r = _generate_private_key_for_kem(backend, kem)
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"Hello!", pk_r)
        plaintext = suite.decrypt(ciphertext, sk_r)

        assert plaintext == b"Hello!"

    @pytest.mark.parametrize("kem", ALL_KEMS)
    def test_wrong_key_fails(self, kem, backend):
        suite = Suite(kem, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = _generate_private_key_for_kem(backend, kem)
        pk_r = sk_r.public_key()
        sk_wrong = _generate_private_key_for_kem(backend, kem)

        ciphertext = suite.encrypt(b"Secret message", pk_r)

        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_wrong)

    @pytest.mark.parametrize("kem", ALL_KEMS)
    def test_wrong_key_type_or_curve(self, kem, backend):
        suite = Suite(kem, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = _generate_private_key_for_kem(backend, kem)
        pk_r = sk_r.public_key()
        ciphertext = suite.encrypt(b"test", pk_r)

        if kem == KEM.X25519:
            wrong_sk = ec.generate_private_key(ec.SECP256R1())
            with pytest.raises(TypeError):
                suite.decrypt(ciphertext, wrong_sk)
            with pytest.raises(TypeError):
                suite.encrypt(b"test", wrong_sk.public_key())
            return

        wrong_x25519_sk = x25519.X25519PrivateKey.generate()
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, wrong_x25519_sk)
        with pytest.raises(TypeError):
            suite.encrypt(b"test", wrong_x25519_sk.public_key())

        wrong_curve = _other_ec_curve(backend, kem)
        if wrong_curve is None:
            pytest.skip("No alternate EC curve available for wrong-curve test")

        wrong_curve_sk = ec.generate_private_key(wrong_curve)
        with pytest.raises(TypeError):
            suite.decrypt(ciphertext, wrong_curve_sk)
        with pytest.raises(TypeError):
            suite.encrypt(b"test", wrong_curve_sk.public_key())

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

    @pytest.mark.parametrize("kem", ALL_KEMS)
    def test_ciphertext_format(self, kem, backend):
        suite = Suite(kem, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = _generate_private_key_for_kem(backend, kem)
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        assert len(ciphertext) == ENC_LENGTHS[kem] + 4 + 16

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

        corrupted = (
            ciphertext[: ENC_LENGTHS[KEM.X25519]]
            + bytes([ciphertext[ENC_LENGTHS[KEM.X25519]] ^ 0xFF])
            + ciphertext[ENC_LENGTHS[KEM.X25519] + 1 :]
        )

        with pytest.raises(InvalidTag):
            suite.decrypt(corrupted, sk_r)

    @pytest.mark.parametrize("kem", ALL_KEMS)
    def test_truncated_ciphertext(self, kem, backend):
        suite = Suite(kem, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = _generate_private_key_for_kem(backend, kem)
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        truncated = ciphertext[:-1]

        with pytest.raises(InvalidTag):
            suite.decrypt(truncated, sk_r)
        with pytest.raises(InvalidTag):
            suite.decrypt(b"\x00", sk_r)

    @pytest.mark.parametrize(
        "small_order_point",
        [
            bytes(32),
            bytes([1] + [0] * 31),
            bytes.fromhex(
                "ecffffffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffff7f"
            ),
            bytes.fromhex(
                "5f9c95bca3508c24b1d0b1559c83ef5b04445cc"
                "4581c8e86d8224eddd09f1157"
            ),
            bytes.fromhex(
                "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb"
                "9c32b1fd866205165f49b800"
            ),
            bytes.fromhex(
                "0000000000000000000000000000000000000000"
                "000000000000000000000080"
            ),
            bytes.fromhex(
                "0100000000000000000000000000000000000000"
                "000000000000000000000080"
            ),
            bytes.fromhex(
                "edffffffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffff"
            ),
        ],
    )
    def test_small_order_enc_raises_invalid_tag(self, small_order_point):
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        sk_r = x25519.X25519PrivateKey.generate()

        fake_ciphertext = small_order_point + b"\x00" * 32

        with pytest.raises(InvalidTag):
            suite.decrypt(fake_ciphertext, sk_r)

    @pytest.mark.parametrize("kem", [KEM.P256, KEM.P384, KEM.P521])
    def test_invalid_ec_enc_raises_invalid_tag(self, kem, backend):
        _skip_kem_if_unsupported(backend, kem)

        suite = Suite(kem, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        sk_r = _generate_private_key_for_kem(backend, kem)

        fake_enc = b"\x04" + b"\x00" * (ENC_LENGTHS[kem] - 1)
        fake_ciphertext = fake_enc + b"\x00" * 32

        with pytest.raises(InvalidTag):
            suite.decrypt(fake_ciphertext, sk_r)

    def test_vector_decryption(self, subtests, backend):
        vectors = load_vectors_from_file(
            os.path.join("HPKE", "test-vectors.json"),
            lambda f: json.load(f),
        )

        kem_map = {
            0x0010: KEM.P256,
            0x0012: KEM.P521,
            0x0020: KEM.X25519,
        }
        kdf_map = {
            0x0001: KDF.HKDF_SHA256,
            0x0003: KDF.HKDF_SHA512,
        }
        aead_map = {
            0x0001: AEAD.AES_128_GCM,
            0x0002: AEAD.AES_256_GCM,
            0x0003: AEAD.CHACHA20_POLY1305,
        }

        for vector in vectors:
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
                suite = Suite(kem, kdf, aead)

                sk_r = _derive_private_key_for_kem(
                    backend, kem, bytes.fromhex(vector["skRm"])
                )
                enc = bytes.fromhex(vector["enc"])
                info = bytes.fromhex(vector["info"])

                encryption = vector["encryptions"][0]
                aad = bytes.fromhex(encryption["aad"])
                ct = bytes.fromhex(encryption["ct"])
                pt_expected = bytes.fromhex(encryption["pt"])

                ciphertext = enc + ct
                pt = rust_openssl.hpke._decrypt_with_aad(
                    suite, ciphertext, sk_r, info=info, aad=aad
                )
                assert pt == pt_expected
