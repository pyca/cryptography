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

import sys

import six

from cryptography import utils
from cryptography.hazmat.primitives import interfaces


def _bit_length(x):
    if sys.version_info >= (2, 7):
        return x.bit_length()
    else:
        return len(bin(x)) - (2 + (x <= 0))


@utils.register_interface(interfaces.RSAPublicKey)
class RSAPublicKey(object):
    def __init__(self, public_exponent, modulus):
        if (
            not isinstance(public_exponent, six.integer_types) or
            not isinstance(modulus, six.integer_types)
        ):
            raise TypeError("RSAPublicKey arguments must be integers")

        if modulus < 3:
            raise ValueError("modulus must be >= 3")

        if public_exponent < 3 or public_exponent >= modulus:
            raise ValueError("public_exponent must be >= 3 and < modulus")

        self._public_exponent = public_exponent
        self._modulus = modulus

    @property
    def key_size(self):
        return _bit_length(self.modulus)

    @property
    def public_exponent(self):
        return self._public_exponent

    @property
    def modulus(self):
        return self._modulus

    @property
    def e(self):
        return self.public_exponent

    @property
    def n(self):
        return self.modulus


@utils.register_interface(interfaces.RSAPrivateKey)
class RSAPrivateKey(object):
    def __init__(self, p, q, private_exponent, public_exponent, modulus):
        if (
            not isinstance(p, six.integer_types) or
            not isinstance(q, six.integer_types) or
            not isinstance(private_exponent, six.integer_types) or
            not isinstance(public_exponent, six.integer_types) or
            not isinstance(modulus, six.integer_types)
        ):
            raise TypeError("RSAPrivateKey arguments must be integers")

        if modulus < 3:
            raise ValueError("modulus must be >= 3")

        if private_exponent >= modulus:
            raise ValueError("private_exponent must be < modulus")

        if public_exponent < 3 or public_exponent >= modulus:
            raise ValueError("public_exponent must be >= 3 and < modulus")

        self._p = p
        self._q = q
        self._private_exponent = private_exponent
        self._public_exponent = public_exponent
        self._modulus = modulus

    @property
    def key_size(self):
        return _bit_length(self.modulus)

    def public_key(self):
        return RSAPublicKey(self.public_exponent, self.modulus)

    @property
    def p(self):
        return self._p

    @property
    def q(self):
        return self._q

    @property
    def private_exponent(self):
        return self._private_exponent

    @property
    def public_exponent(self):
        return self._public_exponent

    @property
    def modulus(self):
        return self._modulus

    @property
    def d(self):
        return self.private_exponent

    @property
    def e(self):
        return self.public_exponent

    @property
    def n(self):
        return self.modulus
