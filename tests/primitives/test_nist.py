"""
Test using the NIST Test Vectors
"""
import binascii
import os

import pytest

from cryptography.primitives.block import BlockCipher, ciphers, modes, padding

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
            os.path.join("AES/MMT", fname),
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        )
    )


class TestAES_CBC(object):
    @parameterize_kat_encrypt("CBCGFSbox128.rsp")
    def test_KAT_GFSbox_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCGFSbox192.rsp")
    def test_KAT_GFSbox_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCGFSbox256.rsp")
    def test_KAT_GFSbox_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCKeySbox128.rsp")
    def test_KAT_KeySbox_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCKeySbox192.rsp")
    def test_KAT_KeySbox_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCKeySbox256.rsp")
    def test_KAT_KeySbox_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCVarKey128.rsp")
    def test_KAT_VarKey_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCVarKey192.rsp")
    def test_KAT_VarKey_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCVarKey256.rsp")
    def test_KAT_VarKey_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCVarTxt128.rsp")
    def test_KAT_VarTxt_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCVarTxt192.rsp")
    def test_KAT_VarTxt_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @parameterize_kat_encrypt("CBCVarTxt256.rsp")
    def test_KAT_VarTxt_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @paramterize_mmt_encrypt("CBCMMT128.rsp")
    def test_MMT_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @paramterize_mmt_encrypt("CBCMMT192.rsp")
    def test_MMT_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @paramterize_mmt_encrypt("CBCMMT256.rsp")
    def test_MMT_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext
