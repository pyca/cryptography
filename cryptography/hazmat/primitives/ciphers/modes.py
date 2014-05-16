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


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class CBC(object):
    name = "CBC"

    def __init__(self, initialization_vector):
        self.initialization_vector = initialization_vector

    def validate_for_algorithm(self, algorithm):
        if len(self.initialization_vector) * 8 != algorithm.block_size:
            raise ValueError("Invalid iv size ({0}) for {1}".format(
                len(self.initialization_vector), self.name
            ))


@utils.register_interface(interfaces.Mode)
class ECB(object):
    name = "ECB"

    def validate_for_algorithm(self, algorithm):
        pass


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class OFB(object):
    name = "OFB"

    def __init__(self, initialization_vector):
        self.initialization_vector = initialization_vector

    def validate_for_algorithm(self, algorithm):
        if len(self.initialization_vector) * 8 != algorithm.block_size:
            raise ValueError("Invalid iv size ({0}) for {1}".format(
                len(self.initialization_vector), self.name
            ))


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class CFB(object):
    name = "CFB"

    def __init__(self, initialization_vector):
        self.initialization_vector = initialization_vector

    def validate_for_algorithm(self, algorithm):
        if len(self.initialization_vector) * 8 != algorithm.block_size:
            raise ValueError("Invalid iv size ({0}) for {1}".format(
                len(self.initialization_vector), self.name
            ))


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class CFB8(object):
    name = "CFB8"

    def __init__(self, initialization_vector):
        self.initialization_vector = initialization_vector

    def validate_for_algorithm(self, algorithm):
        if len(self.initialization_vector) * 8 != algorithm.block_size:
            raise ValueError("Invalid iv size ({0}) for {1}".format(
                len(self.initialization_vector), self.name
            ))


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithNonce)
class CTR(object):
    name = "CTR"

    def __init__(self, nonce):
        self.nonce = nonce

    def validate_for_algorithm(self, algorithm):
        if len(self.nonce) * 8 != algorithm.block_size:
            raise ValueError("Invalid nonce size ({0}) for {1}".format(
                len(self.nonce), self.name
            ))


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
@utils.register_interface(interfaces.ModeWithAuthenticationTag)
class GCM(object):
    name = "GCM"

    def __init__(self, initialization_vector, tag=None):
        # len(initialization_vector) must in [1, 2 ** 64), but it's impossible
        # to actually construct a bytes object that large, so we don't check
        # for it
        if tag is not None and len(tag) < 4:
            raise ValueError(
                "Authentication tag must be 4 bytes or longer"
            )

        self.initialization_vector = initialization_vector
        self.tag = tag

    def validate_for_algorithm(self, algorithm):
        pass
