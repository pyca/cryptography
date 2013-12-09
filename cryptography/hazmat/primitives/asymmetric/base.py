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


class AsymmetricCryptor(object):
    def __init__(self, algorithm, padding):
        self.algorithm = algorithm
        self._backend = algorithm._backend
        self.padding = padding

    def encrypt(self, data):
        buf = self._backend.ffi.new(
            "char[]", self._backend.lib.RSA_size(self.algorithm._ctx)
        )
        bytes_encrypted = self._backend.lib.RSA_public_encrypt(
            len(data), data, buf, self.algorithm._ctx,
            self._backend.lib.RSA_PKCS1_OAEP_PADDING
        )
        assert bytes_encrypted != -1
        return self._backend.ffi.buffer(buf)[:bytes_encrypted]

    def decrypt(self, data):
        buf = self._backend.ffi.new(
            "char[]", self._backend.lib.RSA_size(self.algorithm._ctx)
        )
        bytes_decrypted = self._backend.lib.RSA_private_decrypt(
            len(data), data, buf, self.algorithm._ctx,
            self._backend.lib.RSA_PKCS1_OAEP_PADDING
        )
        assert bytes_decrypted != -1
        return self._backend.ffi.buffer(buf)[:bytes_decrypted]


class AsymmetricSigner(object):
    def __init__(self, algorithm, padding):
        self._ctx = algorithm._ctx._backend.create_signer_ctx(
            algorithm._ctx, padding
        )
        self.algorithm = algorithm
        self.padding = padding

    def sign(self, data):
        return self._ctx.sign(data)

    def verify(self, data):
        return self._ctx.verify(data)
