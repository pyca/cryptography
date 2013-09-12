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

from cryptography.primitives.block import BlockCipher, ciphers, modes


class TestBlockCipher(object):
    def test_cipher_name(self):
        cipher = BlockCipher(
            ciphers.AES(binascii.unhexlify(b"0" * 32)),
            modes.CBC(binascii.unhexlify(b"0" * 32))
        )
        assert cipher.name == "AES-128-CBC"
