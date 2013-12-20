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
from cryptography.hazmat.primitives import interfaces


def generate_rsa_key(bit_length, public_exponent, backend):
    ctx = backend.generate_rsa_ctx(bit_length, public_exponent)
    return RSAPrivateKey(ctx)


@utils.register_interface(interfaces.RSAPrivateKey)
class RSAPrivateKey(object):
    def __init__(self, ctx):
        if not isinstance(ctx, interfaces.RSAPrivateKey):
            raise TypeError("Expected instance of interfaces.RSAPrivateKey.")
        self._ctx = ctx

    @property
    def modulus(self):
        return self._ctx.n

    @property
    def public_exponent(self):
        return self._ctx.e

    @property
    def n(self):
        return self._ctx.n

    @property
    def p(self):
        return self._ctx.p

    @property
    def q(self):
        return self._ctx.q

    @property
    def e(self):
        return self._ctx.e

    @property
    def d(self):
        return self._ctx.d

    @property
    def key_length(self):
        return self._ctx.key_length

    @property
    def public_key(self):
        return self._ctx.public_key
