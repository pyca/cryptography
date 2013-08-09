import binascii

import pytest

from cryptography.primitives.block import BlockCipher, ciphers, modes, padding

from ..utils import load_nist_vectors_from_file


class TestBlockCipher(object):
    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"),
        load_nist_vectors_from_file("AES/KAT/CBCGFSbox256.rsp", "ENCRYPT", ["key", "iv", "plaintext", "ciphertext"])
    )
    def test_aes_cbc_nopadding(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext
