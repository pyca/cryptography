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
    #def __init__(self, modulus, public_exponent, private_exponent, p, q,
    #             crt_coefficient):
    def __init__(self, ctx):
        self._ctx = ctx

    def to_pem(self):
        pass

    @classmethod
    def generate(cls, bit_length, backend):
        ctx = backend.create_rsa_ctx(bit_length)
        return cls(ctx)

    @classmethod
    def from_pkcs1(cls):
        return cls()

    @classmethod
    def from_pkcs8(cls):
        return cls()

    @classmethod
    def from_openssh(cls, text):
        return cls()

    @property
    def keysize(self):
        return self._ctx.keysize
