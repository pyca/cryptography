# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import os

import pytest

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives.ciphers.aead import (
    AESCCM, AESGCM, ChaCha20Poly1305
)

from .utils import _load_all_params
from ...utils import (
    load_nist_ccm_vectors, load_nist_vectors, load_vectors_from_file,
    raises_unsupported_algorithm
)


def _aead_supported(cls):
    try:
        cls(b"0" * 32)
        return True
    except UnsupportedAlgorithm:
        return False


@pytest.mark.skipif(
    _aead_supported(ChaCha20Poly1305),
    reason="Requires OpenSSL without ChaCha20Poly1305 support"
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
def test_chacha20poly1305_unsupported_on_older_openssl(backend):
    with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
        ChaCha20Poly1305(ChaCha20Poly1305.generate_key())


@pytest.mark.skipif(
    not _aead_supported(ChaCha20Poly1305),
    reason="Does not support ChaCha20Poly1305"
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestChaCha20Poly1305(object):
    def test_generate_key(self):
        key = ChaCha20Poly1305.generate_key()
        assert len(key) == 32

    def test_bad_key(self, backend):
        with pytest.raises(TypeError):
            ChaCha20Poly1305(object())

        with pytest.raises(ValueError):
            ChaCha20Poly1305(b"0" * 31)

    @pytest.mark.parametrize(
        ("nonce", "data", "associated_data"),
        [
            [object(), b"data", b""],
            [b"0" * 12, object(), b""],
            [b"0" * 12, b"data", object()]
        ]
    )
    def test_params_not_bytes_encrypt(self, nonce, data, associated_data,
                                      backend):
        key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        with pytest.raises(TypeError):
            chacha.encrypt(nonce, data, associated_data)

        with pytest.raises(TypeError):
            chacha.decrypt(nonce, data, associated_data)

    def test_nonce_not_12_bytes(self, backend):
        key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        with pytest.raises(ValueError):
            chacha.encrypt(b"00", b"hello", b"")

        with pytest.raises(ValueError):
            chacha.decrypt(b"00", b"hello", b"")

    def test_decrypt_data_too_short(self, backend):
        key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        with pytest.raises(InvalidTag):
            chacha.decrypt(b"0" * 12, b"0", None)

    def test_associated_data_none_equal_to_empty_bytestring(self, backend):
        key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ct1 = chacha.encrypt(nonce, b"some_data", None)
        ct2 = chacha.encrypt(nonce, b"some_data", b"")
        assert ct1 == ct2
        pt1 = chacha.decrypt(nonce, ct1, None)
        pt2 = chacha.decrypt(nonce, ct2, b"")
        assert pt1 == pt2

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("ciphers", "ChaCha20Poly1305", "openssl.txt"),
            load_nist_vectors
        )
    )
    def test_openssl_vectors(self, vector, backend):
        key = binascii.unhexlify(vector["key"])
        nonce = binascii.unhexlify(vector["iv"])
        aad = binascii.unhexlify(vector["aad"])
        tag = binascii.unhexlify(vector["tag"])
        pt = binascii.unhexlify(vector["plaintext"])
        ct = binascii.unhexlify(vector["ciphertext"])
        chacha = ChaCha20Poly1305(key)
        if vector.get("result") == b"CIPHERFINAL_ERROR":
            with pytest.raises(InvalidTag):
                chacha.decrypt(nonce, ct + tag, aad)
        else:
            computed_pt = chacha.decrypt(nonce, ct + tag, aad)
            assert computed_pt == pt
            computed_ct = chacha.encrypt(nonce, pt, aad)
            assert computed_ct == ct + tag

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("ciphers", "ChaCha20Poly1305", "boringssl.txt"),
            load_nist_vectors
        )
    )
    def test_boringssl_vectors(self, vector, backend):
        key = binascii.unhexlify(vector["key"])
        nonce = binascii.unhexlify(vector["nonce"])
        if vector["ad"].startswith(b'"'):
            aad = vector["ad"][1:-1]
        else:
            aad = binascii.unhexlify(vector["ad"])
        tag = binascii.unhexlify(vector["tag"])
        if vector["in"].startswith(b'"'):
            pt = vector["in"][1:-1]
        else:
            pt = binascii.unhexlify(vector["in"])
        ct = binascii.unhexlify(vector["ct"].strip(b'"'))
        chacha = ChaCha20Poly1305(key)
        computed_pt = chacha.decrypt(nonce, ct + tag, aad)
        assert computed_pt == pt
        computed_ct = chacha.encrypt(nonce, pt, aad)
        assert computed_ct == ct + tag


@pytest.mark.skipif(
    _aead_supported(AESCCM),
    reason="Requires OpenSSL without AES-CCM support"
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
def test_aesccm_unsupported_on_older_openssl(backend):
    with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
        AESCCM(AESCCM.generate_key(128))


@pytest.mark.skipif(
    not _aead_supported(AESCCM),
    reason="Does not support AESCCM"
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestAESCCM(object):
    def test_default_tag_length(self, backend):
        key = AESCCM.generate_key(128)
        aesccm = AESCCM(key)
        nonce = os.urandom(12)
        pt = b"hello"
        ct = aesccm.encrypt(nonce, pt, None)
        assert len(ct) == len(pt) + 16

    def test_invalid_tag_length(self, backend):
        key = AESCCM.generate_key(128)
        with pytest.raises(ValueError):
            AESCCM(key, tag_length=7)

        with pytest.raises(ValueError):
            AESCCM(key, tag_length=2)

        with pytest.raises(TypeError):
            AESCCM(key, tag_length="notanint")

    def test_invalid_nonce_length(self, backend):
        key = AESCCM.generate_key(128)
        aesccm = AESCCM(key)
        pt = b"hello"
        nonce = os.urandom(14)
        with pytest.raises(ValueError):
            aesccm.encrypt(nonce, pt, None)

        with pytest.raises(ValueError):
            aesccm.encrypt(nonce[:6], pt, None)

    @pytest.mark.parametrize(
        "vector",
        _load_all_params(
            os.path.join("ciphers", "AES", "CCM"),
            [
                "DVPT128.rsp", "DVPT192.rsp", "DVPT256.rsp",
                "VADT128.rsp", "VADT192.rsp", "VADT256.rsp",
                "VNT128.rsp", "VNT192.rsp", "VNT256.rsp",
                "VPT128.rsp", "VPT192.rsp", "VPT256.rsp",
            ],
            load_nist_ccm_vectors
        )
    )
    def test_vectors(self, vector, backend):
        key = binascii.unhexlify(vector["key"])
        nonce = binascii.unhexlify(vector["nonce"])
        adata = binascii.unhexlify(vector["adata"])[:vector["alen"]]
        ct = binascii.unhexlify(vector["ct"])
        pt = binascii.unhexlify(vector["payload"])[:vector["plen"]]
        aesccm = AESCCM(key, vector["tlen"])
        if vector.get('fail'):
            with pytest.raises(InvalidTag):
                aesccm.decrypt(nonce, ct, adata)
        else:
            computed_pt = aesccm.decrypt(nonce, ct, adata)
            assert computed_pt == pt
            assert aesccm.encrypt(nonce, pt, adata) == ct

    def test_roundtrip(self, backend):
        key = AESCCM.generate_key(128)
        aesccm = AESCCM(key)
        pt = b"encrypt me"
        ad = b"additional"
        nonce = os.urandom(12)
        ct = aesccm.encrypt(nonce, pt, ad)
        computed_pt = aesccm.decrypt(nonce, ct, ad)
        assert computed_pt == pt

    def test_nonce_too_long(self, backend):
        key = AESCCM.generate_key(128)
        aesccm = AESCCM(key)
        pt = b"encrypt me" * 6600
        # pt can be no more than 65536 bytes when nonce is 13 bytes
        nonce = os.urandom(13)
        with pytest.raises(ValueError):
            aesccm.encrypt(nonce, pt, None)

    @pytest.mark.parametrize(
        ("nonce", "data", "associated_data"),
        [
            [object(), b"data", b""],
            [b"0" * 12, object(), b""],
            [b"0" * 12, b"data", object()],
        ]
    )
    def test_params_not_bytes(self, nonce, data, associated_data, backend):
        key = AESCCM.generate_key(128)
        aesccm = AESCCM(key)
        with pytest.raises(TypeError):
            aesccm.encrypt(nonce, data, associated_data)

    def test_bad_key(self, backend):
        with pytest.raises(TypeError):
            AESCCM(object())

        with pytest.raises(ValueError):
            AESCCM(b"0" * 31)

    def test_bad_generate_key(self, backend):
        with pytest.raises(TypeError):
            AESCCM.generate_key(object())

        with pytest.raises(ValueError):
            AESCCM.generate_key(129)

    def test_associated_data_none_equal_to_empty_bytestring(self, backend):
        key = AESCCM.generate_key(128)
        aesccm = AESCCM(key)
        nonce = os.urandom(12)
        ct1 = aesccm.encrypt(nonce, b"some_data", None)
        ct2 = aesccm.encrypt(nonce, b"some_data", b"")
        assert ct1 == ct2
        pt1 = aesccm.decrypt(nonce, ct1, None)
        pt2 = aesccm.decrypt(nonce, ct2, b"")
        assert pt1 == pt2

    def test_decrypt_data_too_short(self, backend):
        key = AESCCM.generate_key(128)
        aesccm = AESCCM(key)
        with pytest.raises(InvalidTag):
            aesccm.decrypt(b"0" * 12, b"0", None)


def _load_gcm_vectors():
    vectors = _load_all_params(
        os.path.join("ciphers", "AES", "GCM"),
        [
            "gcmDecrypt128.rsp",
            "gcmDecrypt192.rsp",
            "gcmDecrypt256.rsp",
            "gcmEncryptExtIV128.rsp",
            "gcmEncryptExtIV192.rsp",
            "gcmEncryptExtIV256.rsp",
        ],
        load_nist_vectors
    )
    return [x for x in vectors if len(x["tag"]) == 32]


@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestAESGCM(object):
    @pytest.mark.parametrize("vector", _load_gcm_vectors())
    def test_vectors(self, vector):
        key = binascii.unhexlify(vector["key"])
        nonce = binascii.unhexlify(vector["iv"])
        aad = binascii.unhexlify(vector["aad"])
        ct = binascii.unhexlify(vector["ct"])
        pt = binascii.unhexlify(vector.get("pt", b""))
        tag = binascii.unhexlify(vector["tag"])
        aesgcm = AESGCM(key)
        if vector.get("fail") is True:
            with pytest.raises(InvalidTag):
                aesgcm.decrypt(nonce, ct + tag, aad)
        else:
            computed_ct = aesgcm.encrypt(nonce, pt, aad)
            assert computed_ct[:-16] == ct
            assert computed_ct[-16:] == tag
            computed_pt = aesgcm.decrypt(nonce, ct + tag, aad)
            assert computed_pt == pt

    @pytest.mark.parametrize(
        ("nonce", "data", "associated_data"),
        [
            [object(), b"data", b""],
            [b"0" * 12, object(), b""],
            [b"0" * 12, b"data", object()]
        ]
    )
    def test_params_not_bytes(self, nonce, data, associated_data, backend):
        key = AESGCM.generate_key(128)
        aesgcm = AESGCM(key)
        with pytest.raises(TypeError):
            aesgcm.encrypt(nonce, data, associated_data)

        with pytest.raises(TypeError):
            aesgcm.decrypt(nonce, data, associated_data)

    def test_bad_key(self, backend):
        with pytest.raises(TypeError):
            AESGCM(object())

        with pytest.raises(ValueError):
            AESGCM(b"0" * 31)

    def test_bad_generate_key(self, backend):
        with pytest.raises(TypeError):
            AESGCM.generate_key(object())

        with pytest.raises(ValueError):
            AESGCM.generate_key(129)

    def test_associated_data_none_equal_to_empty_bytestring(self, backend):
        key = AESGCM.generate_key(128)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct1 = aesgcm.encrypt(nonce, b"some_data", None)
        ct2 = aesgcm.encrypt(nonce, b"some_data", b"")
        assert ct1 == ct2
        pt1 = aesgcm.decrypt(nonce, ct1, None)
        pt2 = aesgcm.decrypt(nonce, ct2, b"")
        assert pt1 == pt2
