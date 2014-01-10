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


class RSAPublicKey(object):
    def __init__(self, ctx):
        self._ctx = ctx

    @property
    def modulus(self):
        return self._ctx.modulus

    @property
    def public_exponent(self):
        return self._ctx.public_exponent

    @property
    def keysize(self):
        return self._ctx.keysize


class RSAPrivateKey(object):
    def __init__(self, ctx):
        self._ctx = ctx

    @property
    def keysize(self):
        return self._ctx.keysize

    @property
    def publickey(self):
        return RSAPublicKey(self._ctx.publickey)


class RSA(object):
    public_key_type = RSAPublicKey
    private_key_type = RSAPrivateKey
