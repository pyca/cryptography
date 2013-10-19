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

from cryptography.primitives.block import BlockCipher, ciphers, modes


class TestBlockCipher(object):
    def test_instantiate_without_api(self):
        BlockCipher(
            ciphers.AES(binascii.unhexlify(b"0" * 32)),
            modes.CBC(binascii.unhexlify(b"0" * 32))
        )

    def test_creates_encryptor(self):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(b"0" * 32)),
            modes.CBC(binascii.unhexlify(b"0" * 32))
        )
        assert cipher.encryptor() is not None

    def test_creates_decryptor(self):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(b"0" * 32)),
            modes.CBC(binascii.unhexlify(b"0" * 32))
        )
        assert cipher.decryptor() is not None


class TestBlockCipherContext(object):
    def test_use_after_finalize(self, api):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(b"0" * 32)),
            modes.CBC(binascii.unhexlify(b"0" * 32)),
            api
        )
        context = cipher.encryptor()
        context.update(b"a" * 16)
        context.finalize()
        with pytest.raises(ValueError):
            context.update(b"b" * 16)
        with pytest.raises(ValueError):
            context.finalize()
        context = cipher.decryptor()
        context.update(b"a" * 16)
        context.finalize()
        with pytest.raises(ValueError):
            context.update(b"b" * 16)
        with pytest.raises(ValueError):
            context.finalize()

    def test_unaligned_block_encryption(self, api):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(b"0" * 32)),
            modes.ECB(),
            api
        )
        context = cipher.encryptor()
        ct = context.update(b"a" * 15)
        assert ct == b""
        ct += context.update(b"a" * 65)
        assert len(ct) == 80
        ct += context.finalize()
        context = cipher.decryptor()
        pt = context.update(ct[:3])
        assert pt == b""
        pt += context.update(ct[3:])
        assert len(pt) == 80
        context.finalize()
