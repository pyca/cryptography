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
import binascii
import os

import pytest

from cryptography.primitives.block import BlockCipher, ciphers, modes

from ..utils import load_nist_vectors_from_file


def parameterize_kat_encrypt(fname):
    return pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            os.path.join("AES/KAT/", fname),
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )


def paramterize_mmt_encrypt(fname):
    return pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            os.path.join("AES/MMT/", fname),
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        )
    )


class TestAES_CBC(object):
    @parameterize_kat_encrypt("CBCGFSbox128.rsp")
    def test_KAT_GFSbox_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCGFSbox192.rsp")
    def test_KAT_GFSbox_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCGFSbox256.rsp")
    def test_KAT_GFSbox_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCKeySbox128.rsp")
    def test_KAT_KeySbox_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCKeySbox192.rsp")
    def test_KAT_KeySbox_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCKeySbox256.rsp")
    def test_KAT_KeySbox_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCVarKey128.rsp")
    def test_KAT_VarKey_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCVarKey192.rsp")
    def test_KAT_VarKey_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCVarKey256.rsp")
    def test_KAT_VarKey_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCVarTxt128.rsp")
    def test_KAT_VarTxt_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCVarTxt192.rsp")
    def test_KAT_VarTxt_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCVarTxt256.rsp")
    def test_KAT_VarTxt_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @paramterize_mmt_encrypt("CBCMMT128.rsp")
    def test_MMT_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @paramterize_mmt_encrypt("CBCMMT192.rsp")
    def test_MMT_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @paramterize_mmt_encrypt("CBCMMT256.rsp")
    def test_MMT_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv)),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext
