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

"""
Test using the OpenSSL Test Vectors
"""

from __future__ import absolute_import, division, print_function

import binascii
import itertools
import os

import pytest

from cryptography.bindings.openssl.api import api
from cryptography.primitives.block import BlockCipher, ciphers, modes

from ..utils import load_openssl_vectors_from_file

CAMELLIA_CBC_SUPPORTED = api.supports('camellia-128-cbc')
CAMELLIA_OFB_SUPPORTED = api.supports('camellia-128-ofb')
CAMELLIA_CFB_SUPPORTED = api.supports('camellia-128-cfb')


def parameterize_encrypt_test(cipher, params, fnames):
    return pytest.mark.parametrize(params,
        list(itertools.chain.from_iterable(
            load_openssl_vectors_from_file(os.path.join(cipher, fname))
            for fname in fnames
        ))
    )


@pytest.mark.skipif("not CAMELLIA_CBC_SUPPORTED")
class TestCamelliaCBC(object):

    @parameterize_encrypt_test(
        "Camellia",
        ("key", "iv", "plaintext", "ciphertext"),
        [
            "camellia-cbc.txt",
        ]
    )
    def test_OpenSSL(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.Camellia(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext).upper() == ciphertext


@pytest.mark.skipif("not CAMELLIA_OFB_SUPPORTED")
class TestCamelliaOFB(object):

    @parameterize_encrypt_test(
        "Camellia",
        ("key", "iv", "plaintext", "ciphertext"),
        [
            "camellia-ofb.txt",
        ]
    )
    def test_OpenSSL(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.Camellia(binascii.unhexlify(key)),
            modes.OFB(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext).upper() == ciphertext


@pytest.mark.skipif("not CAMELLIA_CFB_SUPPORTED")
class TestCamelliaCFB(object):

    @parameterize_encrypt_test(
        "Camellia",
        ("key", "iv", "plaintext", "ciphertext"),
        [
            "camellia-cfb.txt",
        ]
    )
    def test_OpenSSL(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.Camellia(binascii.unhexlify(key)),
            modes.CFB(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext).upper() == ciphertext
