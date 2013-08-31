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

from enum import Enum

# TODO: which binding is used should be an option somewhere
from cryptography.bindings.openssl import api


class _Operation(Enum):
    encrypt = 0
    decrypt = 1


class BlockCipher(object):
    def __init__(self, cipher, mode):
        super(BlockCipher, self).__init__()
        self.cipher = cipher
        self.mode = mode
        self._ctx = api.create_block_cipher_context(cipher, mode)
        self._operation = None

    @property
    def name(self):
        return "{0}-{1}-{2}".format(
            self.cipher.name, self.cipher.key_size, self.mode.name,
        )

    def encrypt(self, plaintext):
        if self._ctx is None:
            raise ValueError("BlockCipher was already finalized")

        if self._operation is None:
            self._operation = _Operation.encrypt
        elif self._operation is not _Operation.encrypt:
            raise ValueError("BlockCipher cannot encrypt when the operation is"
                             " set to %s" % self._operation.name)

        return api.update_encrypt_context(self._ctx, plaintext)

    def finalize(self):
        if self._ctx is None:
            raise ValueError("BlockCipher was already finalized")

        if self._operation is _Operation.encrypt:
            result = api.finalize_encrypt_context(self._ctx)
        else:
            raise ValueError("BlockCipher cannot finalize the unknown "
                             "operation %s" % self._operation.name)

        self._ctx = None
        return result
