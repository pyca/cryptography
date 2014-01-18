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

from cryptography import utils
from cryptography.hazmat import interfaces


@utils.register_interface(interfaces.PKCS8PublicKey)
class PKCS8PublicKey(object):
    def __init__(self, backend):
        self._enc_ctx = backend.create_pkcs8_encoder()
        self._dec_ctx = backend.create_pkcs8_decoder()

    def load_pem(self, buffer, password=None):
        return self._dec_ctx.load_pem_public_key(buffer, password)

    def dump_pem(self, public_key):
        return self._enc_ctx.dump_pem_public_key(public_key)


@utils.register_interface(interfaces.PKCS8PrivateKey)
class PKCS8PrivateKey(object):
    def __init__(self, backend):
        self._enc_ctx = backend.create_pkcs8_encoder()
        self._dec_ctx = backend.create_pkcs8_decoder()

    def load_pem(self, buffer, password):
        return self._dec_ctx.load_pem_private_key(buffer, password)

    def dump_pem(self, private_key, cipher, mode, password):
        return self._enc_ctx.dump_pem_private_key(
            private_key,
            cipher,
            mode,
            password
        )
