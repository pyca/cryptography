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


class DHPrivateNumbers(object):
    def __init__(self, public_numbers, private_value):
        if not isinstance(public_numbers, DHPublicNumbers):
            raise TypeError("public_numbers must be an instance of "
                            "DHPublicNumbers.")

        if not isinstance(private_value, int):
            raise TypeError("private_value must be an integer.")

        self._public_numbers = public_numbers
        self._private_value = private_value

    @property
    def public_numbers(self):
        return self._public_numbers

    @property
    def private_value(self):
        return self._private_value


class DHPublicNumbers(object):
    def __init__(self, parameters, public_value):
        if not isinstance(parameters, DHParameters):
            raise TypeError("parameters must be an instance of DHParameters.")

        if not isinstance(public_value, int):
            raise TypeError("public_value must be an integer.")

        self._parameters = parameters
        self._public_value = public_value

    @property
    def public_value(self):
        return self._public_value

    @property
    def parameters(self):
        return self._parameters


class DHParameters(object):
    def __init__(self, modulus, generator):
        if (
            not isinstance(modulus, int) or
            not isinstance(generator, int)
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
