import binascii

import pytest

from cryptography.primitives.block import BlockCipher, ciphers, modes, padding


class TestBlockCipher(object):
    @pytest.mark.parametrize(("key", "iv", "plaintext", "ciphertext"), [
        (
            b"9dc2c84a37850c11699818605f47958c",
            b"256953b2feab2a04ae0180d8335bbed6",
            b"2e586692e647f5028ec6fa47a55a2aab",
            b"1b1ebd1fc45ec43037fd4844241a437f"
        ),
    ])
    def test_aes_cbc_nopadding(self, key, iv, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(key)),
            modes.CBC(binascii.unhexlify(iv), padding.NoPadding())
        )
        actual_ciphertext = cipher.encrypt(plaintext) + cipher.finalize()
        assert binascii.hexlify(actual_ciphertext) == ciphertext
