import binascii

import pytest

from cryptography.primitives.block import BlockCipher, ciphers, modes, padding


class TestBlockCipher(object):
    def test_use_after_finalize(self):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(b"0" * 32)),
            modes.CBC(binascii.unhexlify(b"0" * 32), padding.NoPadding())
        )
        cipher.encrypt(b"a" * 16)
        cipher.finalize()
        with pytest.raises(ValueError):
            cipher.encrypt(b"b" * 16)
        with pytest.raises(ValueError):
            cipher.finalize()
