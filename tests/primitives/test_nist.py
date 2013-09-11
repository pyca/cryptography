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
Test using the NIST Test Vectors
"""

from __future__ import absolute_import, division, print_function

import binascii
import itertools
import os

import pytest

from cryptography.primitives.block import BlockCipher, ciphers, modes

from ..utils import load_nist_vectors_from_file


def parameterize_encrypt_test(cipher, vector_type, params, fnames):
    return pytest.mark.parametrize(params,
        list(itertools.chain.from_iterable(
            load_nist_vectors_from_file(
                os.path.join(cipher, vector_type, fname),
                "ENCRYPT",
                params
            )
            for fname in fnames
        ))
    )


class TestAES_CBC(object):
    @parameterize_encrypt_test(
        "AES", "KAT",
        ("key", "iv", "plaintext", "ciphertext"),
        [
            "CBCGFSbox128.rsp",
            "CBCGFSbox192.rsp",
            "CBCGFSbox256.rsp",
            "CBCKeySbox128.rsp",
            "CBCKeySbox192.rsp",
            "CBCKeySbox256.rsp",
            "CBCVarKey128.rsp",
            "CBCVarKey192.rsp",
            "CBCVarKey256.rsp",
            "CBCVarTxt128.rsp",
            "CBCVarTxt192.rsp",
            "CBCVarTxt256.rsp",
        ]
    )
    def test_KAT(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_encrypt_test(
        "AES", "MMT",
        ("key", "iv", "plaintext", "ciphertext"),
        [
            "CBCMMT128.rsp",
            "CBCMMT192.rsp",
            "CBCMMT256.rsp",
        ]
    )
    def test_MMT(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext


class TestTripleDES_CBC(object):
    @parameterize_encrypt_test(
        "3DES", "KAT",
        ("keys", "iv", "plaintext", "ciphertext"),
        [
            "TCBCinvperm.rsp",
            "TCBCpermop.rsp",
            "TCBCsubtab.rsp",
            "TCBCvarkey.rsp",
            "TCBCvartext.rsp",
        ]
    )
    def test_KAT_1(self, keys, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.TripleDES(binascii.unhexlify(keys)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_encrypt_test(
        "3DES", "KAT",
        ("keys", "iv1", "iv2", "iv3", "plaintext", "ciphertext3"),
        [
            "TCBCIpermop.rsp",
            "TCBCIsubtab.rsp",
            "TCBCIvarkey.rsp",
            "TCBCIvartext.rsp",
        ]
    )
    def test_KAT_2(self, keys, iv1, iv2, iv3, plaintext, ciphertext3):
        cipher = BlockCipher(
            ciphers.TripleDES(binascii.unhexlify(keys)),
            modes.CBC(binascii.unhexlify(iv1 + iv2 + iv3)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext3

    @parameterize_encrypt_test(
        "3DES", "KAT",
        ("keys", "iv1", "iv2", "iv3", "plaintext1", "ciphertext3"),
        [
            "TCBCIinvperm.rsp",
        ]
    )
    def test_KAT_3(self, keys, iv1, iv2, iv3, plaintext1, ciphertext3):
        cipher = BlockCipher(
            ciphers.TripleDES(binascii.unhexlify(keys)),
            modes.CBC(binascii.unhexlify(iv1 + iv2 + iv3)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext1))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext3

    @parameterize_encrypt_test(
        "3DES", "MMT",
        ("key1", "key2", "key3", "iv1", "iv2", "iv3", "plaintext", "ciphertext"),
        [
            "TCBCIMMT1.rsp",
            "TCBCIMMT2.rsp",
            "TCBCIMMT3.rsp",
        ]
    )
    def test_MMT_1(self, key1, key2, key3, iv1, iv2, iv3, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.TripleDES(binascii.unhexlify(key1 + key2 + key3)),
            modes.CBC(binascii.unhexlify(iv1 + iv2 + iv3)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_encrypt_test(
        "3DES", "MMT",
        ("key1", "key2", "key3", "iv", "plaintext", "ciphertext"),
        [
            "TCBCMMT1.rsp",
            "TCBCMMT2.rsp",
            "TCBCMMT3.rsp",
        ]
    )
    def test_MMT_2(self, key1, key2, key3, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.TripleDES(binascii.unhexlify(key1 + key2 + key3)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext
