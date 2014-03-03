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


@utils.register_interface(interfaces.DSAParams)
class DSAParams(object):
    def __init__(self, modulus, subgroup_order, generator):
        if (
            not isinstance(modulus, six.integer_types) or
            not isinstance(subgroup_order, six.integer_types) or
            not isinstance(generator, six.integer_types)
        ):
            raise TypeError("DSAParams arguments must be integers")

        if _bit_length(modulus) < 1024:
            raise ValueError("Prime Modulus length must be at least 1024 bits")

        if _bit_length(subgroup_order) < 160:
            raise ValueError("Subgroup order length must be at least 160 bits")

        if generator <= 1:
            raise ValueError("Generator must be > 1")

        if generator >= modulus:
            raise ValueError("Generator must be < Prime Modulus")

        self._modulus = modulus
        self._subgroup_order = subgroup_order
        self._generator = generator

    @classmethod
    def generate(cls, key_size, backend):
        return backend.generate_dsa_parameters(key_size)

    @property
    def modulus(self):
        return self._modulus

    @property
    def subgroup_order(self):
        return self._subgroup_order

    @property
    def generator(self):
        return self._generator

    @property
    def p(self):
        return self.modulus

    @property
    def q(self):
        return self.subgroup_order

    @property
    def g(self):
        return self.generator


@utils.register_interface(interfaces.DSAPrivateKey)
class DSAPrivateKey(object):
    def __init__(self, modulus, subgroup_order, generator, x, y):
        if (
            not isinstance(modulus, six.integer_types) or
            not isinstance(subgroup_order, six.integer_types) or
            not isinstance(generator, six.integer_types) or
            not isinstance(x, six.integer_types) or
            not isinstance(y, six.integer_types)
        ):
            raise TypeError("DSAPrivateKey arguments must be integers")

        if _bit_length(modulus) < 1024:
            raise ValueError("Prime Modulus length must be at least 1024 bits")

        if _bit_length(subgroup_order) < 160:
            raise ValueError("Subgroup order length must be at least 160 bits")

        if generator <= 1:
            raise ValueError("Generator must be > 1")

        if generator >= modulus:
            raise ValueError("Generator must be < Prime Modulus")

        self._modulus = modulus
        self._subgroup_order = subgroup_order
        self._generator = generator
        self._x = y
        self._y = y

    @classmethod
    def generate(cls, backend, parameters=None, key_size=None):
        return backend.generate_dsa_private_key(parameters, key_size)

    @property
    def key_size(self):
        return _bit_length(self._modulus)

    def public_key(self):
        return DSAPublicKey(self._modulus, self._subgroup_order,
                            self._generator, self.y)

    @property
    def x(self):
        return self._x

    @property
    def y(self):
        return self._y

    @property
    def parameters(self):
        return DSAParams(self._modulus, self._subgroup_order, self._generator)


@utils.register_interface(interfaces.DSAPublicKey)
class DSAPublicKey(object):
    def __init__(self, modulus, subgroup_order, generator, y):
        if (
            not isinstance(modulus, six.integer_types) or
            not isinstance(subgroup_order, six.integer_types) or
            not isinstance(generator, six.integer_types) or
            not isinstance(y, six.integer_types)
        ):
            raise TypeError("DSAParams arguments must be integers")

        if _bit_length(modulus) < 1024:
            raise ValueError("Prime Modulus length must be at least 1024 bits")

        if _bit_length(subgroup_order) < 160:
            raise ValueError("Subgroup order length must be at least 160 bits")

        if generator <= 1:
            raise ValueError("Generator must be > 1")

        if generator >= modulus:
            raise ValueError("Generator must be < Prime Modulus")

        self._modulus = modulus
        self._subgroup_order = subgroup_order
        self._generator = generator
        self._y = y

    @property
    def y(self):
        return self._y

    @property
    def parameters(self):
        return DSAParams(self._modulus, self._subgroup_order, self._generator)
