"""
Test using the NIST Test Vectors
"""
import binascii

import pytest

from cryptography.primitives.block import BlockCipher, ciphers, modes, padding

from ..utils import load_nist_vectors_from_file


class TestAES_CBC(object):
    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            "AES/KAT/CBCGFSbox128.rsp",
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )
    def test_KAT_GFSbox_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            "AES/KAT/CBCGFSbox192.rsp",
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )
    def test_KAT_GFSbox_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            "AES/KAT/CBCGFSbox256.rsp",
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )
    def test_KAT_GFSbox_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            "AES/KAT/CBCKeySbox128.rsp",
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )
    def test_KAT_KeySbox_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            "AES/KAT/CBCKeySbox192.rsp",
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )
    def test_KAT_KeySbox_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            "AES/KAT/CBCKeySbox256.rsp",
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )
    def test_KAT_KeySbox_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            "AES/KAT/CBCVarKey128.rsp",
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )
    def test_KAT_VarKey_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            "AES/KAT/CBCVarKey192.rsp",
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )
    def test_KAT_VarKey_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            "AES/KAT/CBCVarKey256.rsp",
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )
    def test_KAT_VarKey_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            "AES/KAT/CBCVarTxt128.rsp",
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )
    def test_KAT_VarTxt_128_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            "AES/KAT/CBCVarTxt192.rsp",
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )
    def test_KAT_VarTxt_192_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext

    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file(
            "AES/KAT/CBCVarTxt256.rsp",
            "ENCRYPT",
            ["key", "iv", "plaintext", "ciphertext"],
        ),
    )
    def test_KAT_VarTxt_256_encrypt(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext
