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
from cryptography.hazmat.x509 import interfaces


@utils.register_interface(interfaces.X509DecoderContext)
class X509Decoder(object):
    def __init__(self, backend):
        self._ctx = backend.create_x509_decoder()

    def pkcs8_private_key(self, buffer, password_callback):
        return self._ctx.pkcs8_private_key(buffer, password_callback)

    def pkcs1_public_key(self, buffer):
        return self._ctx.pkcs1_public_key(buffer)


@utils.register_interface(interfaces.X509EncoderContext)
class X509Encoder(object):
    def __init__(self, backend):
        self._ctx = backend.create_x509_encoder()

    def pkcs8_private_key(self, buffer, password_callback):
        return self._ctx.pkcs8_private_key(buffer, password_callback)

    def pkcs1_public_key(self, public_key):
        return self._ctx.pkcs1_public_key(public_key)
