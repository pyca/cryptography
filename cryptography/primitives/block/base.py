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

# TODO: which binding is used should be an option somewhere
from cryptography.bindings.openssl import api


class BlockCipher(object):
    def __init__(self, cipher, mode):
        super(BlockCipher, self).__init__()
        self.cipher = cipher
        self.mode = mode
        self._ctx = api.create_block_cipher_context(cipher, mode)

    def encrypt(self, plaintext):
        if self._ctx is None:
            raise ValueError("BlockCipher was already finalized")
        return api.update_encrypt_context(self._ctx, plaintext)

    def finalize(self):
        if self._ctx is None:
            raise ValueError("BlockCipher was already finalized")
        # TODO: this might be a decrypt context
        result = api.finalize_encrypt_context(self._ctx)
        self._ctx = None
        return result
