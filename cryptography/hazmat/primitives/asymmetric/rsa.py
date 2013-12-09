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


class RSAPrivateKey(object):
    def __init__(self, ctx):
        self._ctx = ctx

    @classmethod
    def generate(cls, backend, bit_length):
        ctx = backend.create_rsa_ctx(bit_length)
        return cls(ctx)

    @classmethod
    def from_pkcs1(cls, backend, data, form, password=None):
        ctx = backend.create_rsa_ctx_from_pkcs1(data, form, password)
        return cls(ctx)

    @classmethod
    def from_pkcs8(cls, backend, data, form, password=None):
        ctx = backend.create_rsa_ctx_from_pkcs8(data, form, password)
        return cls(ctx)

    @classmethod
    def from_openssh(cls, text):
        return cls()

    @property
    def keysize(self):
        return self._ctx.keysize

    @property
    def publickey(self):
        return RSAPublicKey(self._ctx.publickey)

    def to_pkcs8(self, form, password=None):
        return self._ctx.to_pkcs8(form, password)


class RSAPublicKey(object):
    def __init__(self, ctx):
        self._ctx = ctx

    @classmethod
    def from_modulus(cls, backend, modulus, exponent):
        ctx = backend.create_rsa_pub_ctx_from_modulus(modulus, exponent)
        return cls(ctx)

    @property
    def modulus(self):
        return self._ctx.modulus

    @property
    def public_exponent(self):
        return self._ctx.public_exponent

    @property
    def keysize(self):
        return self._ctx.keysize
