# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import cffi

from pkg_resources import parse_version

import pytest

from cryptography.exceptions import InternalError, _Reasons
from cryptography.hazmat.backends import _available_backends
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC, GCM

from ...doubles import DummyCipherAlgorithm
from ...utils import raises_unsupported_algorithm


@pytest.mark.skipif("commoncrypto" not in
                    [i.name for i in _available_backends()],
                    reason="CommonCrypto not available")
class TestCommonCrypto(object):
    def test_supports_cipher(self):
        from cryptography.hazmat.backends.commoncrypto.backend import backend
        assert backend.cipher_supported(None, None) is False

    def test_register_duplicate_cipher_adapter(self):
        from cryptography.hazmat.backends.commoncrypto.backend import backend
        with pytest.raises(ValueError):
            backend._register_cipher_adapter(
                AES, backend._lib.kCCAlgorithmAES128,
                CBC, backend._lib.kCCModeCBC
            )

    def test_handle_response(self):
        from cryptography.hazmat.backends.commoncrypto.backend import backend

        with pytest.raises(ValueError):
            backend._check_cipher_response(backend._lib.kCCAlignmentError)

        with pytest.raises(InternalError):
            backend._check_cipher_response(backend._lib.kCCMemoryFailure)

        with pytest.raises(InternalError):
            backend._check_cipher_response(backend._lib.kCCDecodeError)

    def test_nonexistent_aead_cipher(self):
        from cryptography.hazmat.backends.commoncrypto.backend import Backend
        b = Backend()
        cipher = Cipher(
            DummyCipherAlgorithm(), GCM(b"fake_iv_here"), backend=b,
        )
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            cipher.encryptor()

    @pytest.mark.skipif(
        parse_version(cffi.__version__) < parse_version('1.7'),
        reason="cffi version too old"
    )
    def test_update_into_gcm_buffer_too_small(self):
        from cryptography.hazmat.backends.commoncrypto.backend import backend
        key = b"\x00" * 16
        c = Cipher(AES(key), GCM(b"0" * 12), backend)
        encryptor = c.encryptor()
        buf = bytearray(5)
        with pytest.raises(ValueError):
            encryptor.update_into(b"testing", buf)
