# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import binascii

import pytest

from cryptography import utils
from cryptography.exceptions import InternalError, _Reasons
from cryptography.hazmat.backends import _available_backends
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.base import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC, GCM

from ...utils import raises_unsupported_algorithm


@utils.register_interface(interfaces.CipherAlgorithm)
class DummyCipher(object):
    name = "dummy-cipher"
    block_size = 128


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
            DummyCipher(), GCM(b"fake_iv_here"), backend=b,
        )
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            cipher.encryptor()

    def test_gcm_tag_with_only_aad(self):
        from cryptography.hazmat.backends.commoncrypto.backend import Backend
        b = Backend()
        key = binascii.unhexlify("1dde380d6b04fdcb004005b8a77bd5e3")
        iv = binascii.unhexlify("5053bf901463f97decd88c33")
        aad = binascii.unhexlify("f807f5f6133021d15cb6434d5ad95cf7d8488727")
        tag = binascii.unhexlify("4bebf3ff2cb67bb5444dda53bd039e22")

        cipher = Cipher(AES(key), GCM(iv), backend=b)
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        encryptor.finalize()
        assert encryptor.tag == tag

    def test_gcm_ciphertext_with_no_aad(self):
        from cryptography.hazmat.backends.commoncrypto.backend import Backend
        b = Backend()
        key = binascii.unhexlify("e98b72a9881a84ca6b76e0f43e68647a")
        iv = binascii.unhexlify("8b23299fde174053f3d652ba")
        ct = binascii.unhexlify("5a3c1cf1985dbb8bed818036fdd5ab42")
        tag = binascii.unhexlify("23c7ab0f952b7091cd324835043b5eb5")
        pt = binascii.unhexlify("28286a321293253c3e0aa2704a278032")

        cipher = Cipher(AES(key), GCM(iv), backend=b)
        encryptor = cipher.encryptor()
        computed_ct = encryptor.update(pt) + encryptor.finalize()
        assert computed_ct == ct
        assert encryptor.tag == tag
