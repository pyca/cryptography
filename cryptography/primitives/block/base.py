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

import six

# TODO: which binding is used should be an option somewhere
from cryptography.bindings.openssl import api


class BlockCipher(object):
    def __init__(self, cipher, mode):
        super(BlockCipher, self).__init__()
        self.cipher = cipher
        self.mode = mode

    @property
    def name(self):
        return "{0}-{1}-{2}".format(
            self.cipher.name, self.cipher.key_size, self.mode.name,
        )

    def iter_encrypt(self, plaintext):
        byte_size = self.cipher.block_size // 8
        ctx = api.create_block_cipher_context(self.cipher, self.mode)

        buf = b""
        for chunk in plaintext:
            if isinstance(chunk, six.integer_types):
                chunk = six.int2byte(chunk)

            buf += chunk

            while len(buf) >= byte_size:
                next_chunk, buf = buf[:byte_size], buf[byte_size:]
                yield api.update_encrypt_context(ctx, next_chunk)

        yield api.finalize_encrypt_context(ctx)

    def encrypt(self, plaintext):
        return b"".join(self.iter_encrypt(plaintext))
