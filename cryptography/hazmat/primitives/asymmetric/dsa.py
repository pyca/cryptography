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


@utils.register_interface(interfaces.DSAPrivateKey)
class DSAPrivateKey(object):
    def __init__(self, modulus, divisor, generator, private_key, public_key):
        if (
            not isinstance(modulus, six.integer_types) or
            not isinstance(divisor, six.integer_types) or
            not isinstance(generator, six.integer_types) or
            not isinstance(private_key, six.integer_types) or
            not isinstance(public_key, six.integer_types)
        ):
            raise TypeError("DSAPrivateKey arguments must be integers")

        self._modulus = modulus
        self._modulus_length = _bit_length(self._modulus)
        self._divisor = divisor
        self._divisor_length = _bit_length(self._divisor)
        self._generator = generator
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def generate(cls, modulus_length, backend):
        return backend.generate_dsa_private_key(modulus_length)

    @property
    def modulus(self):
        return _bit_length(self.modulus)

    @property
    def divisor(self):
        return self._public_exponent

    @property
    def generator(self):
        return self._generator

    @property
    def modulus_length(self):
        return self._modulus_length

    @property
    def divisor_length(self):
        return self._divisor_length

    @property
    def public_key(self):
        return self._public_key

    @property
    def p(self):
        return self.modulus

    @property
    def q(self):
        return self.divisor

    @property
    def g(self):
        return self.generator

    @property
    def L(self):
        return self.modulus_length

    @property
    def N(self):
        return self.divisor_length

    @property
    def y(self):
        return self.public_key
