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


def _check_dsa_parameters(modulus, subgroup_order, generator):
    if (
        not isinstance(modulus, six.integer_types) or
        not isinstance(subgroup_order, six.integer_types) or
        not isinstance(generator, six.integer_types)
    ):
        raise TypeError("DSA parameters must be integers")

    if (utils.bit_length(modulus),
        utils.bit_length(subgroup_order)) not in (
            (1024, 160),
            (2048, 256),
            (3072, 256)):
        raise ValueError("modulus and subgroup_order lengths must be "
                         "one of these pairs (1024, 160) or (2048, 256) "
                         "or (3072, 256)")

    if generator <= 1 or generator >= modulus:
        raise ValueError("generator must be > 1 and < modulus")


@utils.register_interface(interfaces.DSAParameters)
class DSAParameters(object):
    def __init__(self, modulus, subgroup_order, generator):
        _check_dsa_parameters(modulus, subgroup_order, generator)

        self._modulus = modulus
        self._subgroup_order = subgroup_order
        self._generator = generator

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
