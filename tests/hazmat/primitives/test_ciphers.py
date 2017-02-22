# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import os

import cffi

import pytest

from cryptography.exceptions import _Reasons
from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers.algorithms import (
    AES, ARC4, Blowfish, CAST5, Camellia, IDEA, SEED, TripleDES
)
from cryptography.utils import _version_check

from ...utils import (
    load_nist_vectors, load_vectors_from_file, raises_unsupported_algorithm
)


class TestAES(object):
    @pytest.mark.parametrize(("key", "keysize"), [
        (b"0" * 32, 128),
        (b"0" * 48, 192),
        (b"0" * 64, 256),
    ])
    def test_key_size(self, key, keysize):
        cipher = AES(binascii.unhexlify(key))
        assert cipher.key_size == keysize

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            AES(binascii.unhexlify(b"0" * 12))


class TestCamellia(object):
    @pytest.mark.parametrize(("key", "keysize"), [
        (b"0" * 32, 128),
        (b"0" * 48, 192),
        (b"0" * 64, 256),
    ])
    def test_key_size(self, key, keysize):
        cipher = Camellia(binascii.unhexlify(key))
        assert cipher.key_size == keysize

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            Camellia(binascii.unhexlify(b"0" * 12))


class TestTripleDES(object):
    @pytest.mark.parametrize("key", [
        b"0" * 16,
        b"0" * 32,
        b"0" * 48,
    ])
    def test_key_size(self, key):
        cipher = TripleDES(binascii.unhexlify(key))
        assert cipher.key_size == 192

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            TripleDES(binascii.unhexlify(b"0" * 12))


class TestBlowfish(object):
    @pytest.mark.parametrize(("key", "keysize"), [
        (b"0" * (keysize // 4), keysize) for keysize in range(32, 449, 8)
    ])
    def test_key_size(self, key, keysize):
        cipher = Blowfish(binascii.unhexlify(key))
        assert cipher.key_size == keysize

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            Blowfish(binascii.unhexlify(b"0" * 6))


class TestCAST5(object):
    @pytest.mark.parametrize(("key", "keysize"), [
        (b"0" * (keysize // 4), keysize) for keysize in range(40, 129, 8)
    ])
    def test_key_size(self, key, keysize):
        cipher = CAST5(binascii.unhexlify(key))
        assert cipher.key_size == keysize

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            CAST5(binascii.unhexlify(b"0" * 34))


class TestARC4(object):
    @pytest.mark.parametrize(("key", "keysize"), [
        (b"0" * 10, 40),
        (b"0" * 14, 56),
        (b"0" * 16, 64),
        (b"0" * 20, 80),
        (b"0" * 32, 128),
        (b"0" * 48, 192),
        (b"0" * 64, 256),
    ])
    def test_key_size(self, key, keysize):
        cipher = ARC4(binascii.unhexlify(key))
        assert cipher.key_size == keysize

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            ARC4(binascii.unhexlify(b"0" * 34))


class TestIDEA(object):
    def test_key_size(self):
        cipher = IDEA(b"\x00" * 16)
        assert cipher.key_size == 128

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            IDEA(b"\x00" * 17)


class TestSEED(object):
    def test_key_size(self):
        cipher = SEED(b"\x00" * 16)
        assert cipher.key_size == 128

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            SEED(b"\x00" * 17)


def test_invalid_backend():
    pretend_backend = object()

    with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
        ciphers.Cipher(AES(b"AAAAAAAAAAAAAAAA"), modes.ECB, pretend_backend)


@pytest.mark.skipif(
    not _version_check(cffi.__version__, '1.7'),
    reason="cffi version too old"
)
@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        AES(b"\x00" * 16), modes.ECB()
    ),
    skip_message="Does not support AES ECB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestCipherUpdateInto(object):
    @pytest.mark.parametrize(
        "params",
        load_vectors_from_file(
            os.path.join("ciphers", "AES", "ECB", "ECBGFSbox128.rsp"),
            load_nist_vectors
        )
    )
    def test_update_into(self, params, backend):
        key = binascii.unhexlify(params["key"])
        pt = binascii.unhexlify(params["plaintext"])
        ct = binascii.unhexlify(params["ciphertext"])
        c = ciphers.Cipher(AES(key), modes.ECB(), backend)
        encryptor = c.encryptor()
        buf = bytearray(len(pt) + 15)
        res = encryptor.update_into(pt, buf)
        assert res == len(pt)
        assert bytes(buf)[:res] == ct

    @pytest.mark.supported(
        only_if=lambda backend: backend.cipher_supported(
            AES(b"\x00" * 16), modes.GCM(b"0" * 12)
        ),
        skip_message="Does not support AES GCM",
    )
    def test_update_into_gcm(self, backend):
        key = binascii.unhexlify(b"e98b72a9881a84ca6b76e0f43e68647a")
        iv = binascii.unhexlify(b"8b23299fde174053f3d652ba")
        ct = binascii.unhexlify(b"5a3c1cf1985dbb8bed818036fdd5ab42")
        pt = binascii.unhexlify(b"28286a321293253c3e0aa2704a278032")
        c = ciphers.Cipher(AES(key), modes.GCM(iv), backend)
        encryptor = c.encryptor()
        buf = bytearray(len(pt) + 15)
        res = encryptor.update_into(pt, buf)
        assert res == len(pt)
        assert bytes(buf)[:res] == ct
        encryptor.finalize()
        c = ciphers.Cipher(AES(key), modes.GCM(iv, encryptor.tag), backend)
        decryptor = c.decryptor()
        res = decryptor.update_into(ct, buf)
        decryptor.finalize()
        assert res == len(pt)
        assert bytes(buf)[:res] == pt

    @pytest.mark.parametrize(
        "params",
        load_vectors_from_file(
            os.path.join("ciphers", "AES", "ECB", "ECBGFSbox128.rsp"),
            load_nist_vectors
        )
    )
    def test_update_into_multiple_calls(self, params, backend):
        key = binascii.unhexlify(params["key"])
        pt = binascii.unhexlify(params["plaintext"])
        ct = binascii.unhexlify(params["ciphertext"])
        c = ciphers.Cipher(AES(key), modes.ECB(), backend)
        encryptor = c.encryptor()
        buf = bytearray(len(pt) + 15)
        res = encryptor.update_into(pt[:3], buf)
        assert res == 0
        res = encryptor.update_into(pt[3:], buf)
        assert res == len(pt)
        assert bytes(buf)[:res] == ct

    def test_update_into_buffer_too_small(self, backend):
        key = b"\x00" * 16
        c = ciphers.Cipher(AES(key), modes.ECB(), backend)
        encryptor = c.encryptor()
        buf = bytearray(16)
        with pytest.raises(ValueError):
            encryptor.update_into(b"testing", buf)

    @pytest.mark.supported(
        only_if=lambda backend: backend.cipher_supported(
            AES(b"\x00" * 16), modes.GCM(b"\x00" * 12)
        ),
        skip_message="Does not support AES GCM",
    )
    def test_update_into_buffer_too_small_gcm(self, backend):
        key = b"\x00" * 16
        c = ciphers.Cipher(AES(key), modes.GCM(b"\x00" * 12), backend)
        encryptor = c.encryptor()
        buf = bytearray(5)
        with pytest.raises(ValueError):
            encryptor.update_into(b"testing", buf)


@pytest.mark.skipif(
    _version_check(cffi.__version__, '1.7'),
    reason="cffi version too new"
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestCipherUpdateIntoUnsupported(object):
    def _too_old(self, mode, backend):
        key = b"\x00" * 16
        c = ciphers.Cipher(AES(key), mode, backend)
        encryptor = c.encryptor()
        buf = bytearray(32)
        with pytest.raises(NotImplementedError):
            encryptor.update_into(b"\x00" * 16, buf)

    @pytest.mark.supported(
        only_if=lambda backend: backend.cipher_supported(
            AES(b"\x00" * 16), modes.ECB()
        ),
        skip_message="Does not support AES ECB",
    )
    def test_cffi_too_old_ecb(self, backend):
        self._too_old(modes.ECB(), backend)

    @pytest.mark.supported(
        only_if=lambda backend: backend.cipher_supported(
            AES(b"\x00" * 16), modes.CTR(b"0" * 16)
        ),
        skip_message="Does not support AES CTR",
    )
    def test_cffi_too_old_ctr(self, backend):
        self._too_old(modes.CTR(b"0" * 16), backend)

    @pytest.mark.supported(
        only_if=lambda backend: backend.cipher_supported(
            AES(b"\x00" * 16), modes.GCM(b"0" * 16)
        ),
        skip_message="Does not support AES GCM",
    )
    def test_cffi_too_old_gcm(self, backend):
        self._too_old(modes.GCM(b"0" * 16), backend)
