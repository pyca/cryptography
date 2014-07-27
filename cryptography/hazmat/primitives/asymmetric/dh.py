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

import six

from cryptography import utils
from cryptography.hazmat.primitives import interfaces


def generate_parameters(generator, key_size, backend):
    return backend.generate_dh_parameters(generator, key_size)


def generate_private_key(generator, key_size, backend):
    return backend.generate_dh_private_key_and_parameters(generator, key_size)


class DHPrivateNumbers(object):
    def __init__(self, public_numbers, private_value):
        if not isinstance(public_numbers, DHPublicNumbers):
            raise TypeError("public_numbers must be an instance of "
                            "DHPublicNumbers.")

        if not isinstance(private_value, six.integer_types):
            raise TypeError("private_value must be an integer.")

        self._public_numbers = public_numbers
        self._private_value = private_value

    @property
    def public_numbers(self):
        return self._public_numbers

    @property
    def private_value(self):
        return self._private_value

    @property
    def x(self):
        return self._private_value

    def private_key(self, backend):
        return backend.load_dh_private_numbers(self)


class DHPublicNumbers(object):
    def __init__(self, parameter_numbers, public_value):
        if not isinstance(parameter_numbers, DHParameterNumbers):
            raise TypeError(
                "parameters must be an instance of DHParameterNumbers.")

        if not isinstance(public_value, six.integer_types):
            raise TypeError("public_value must be an integer.")

        self._parameters = parameter_numbers
        self._public_value = public_value

    @property
    def public_value(self):
        return self._public_value

    @property
    def y(self):
        return self._public_value

    @property
    def parameter_numbers(self):
        return self._parameters

    def public_key(self, backend):
        return backend.load_dh_public_numbers(self)


class DHParameterNumbers(object):
    def __init__(self, modulus, generator):
        if (
            not isinstance(modulus, six.integer_types) or
            not isinstance(generator, six.integer_types)
        ):
            raise TypeError("modulus and generator must be integers")

        self._modulus = modulus
        self._generator = generator

    @property
    def modulus(self):
        return self._modulus

    @property
    def generator(self):
        return self._generator

    @property
    def p(self):
        return self._modulus

    @property
    def g(self):
        return self._generator

    def parameters(self, backend):
        backend.load_dh_parameter_numbers(self)


@utils.register_interface(interfaces.DHExchangeAlgorithm)
class TLSKeyExchange(object):
    pass
