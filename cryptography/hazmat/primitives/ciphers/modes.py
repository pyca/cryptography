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


def _check_iv_length(mode, algorithm):
    if len(mode.initialization_vector) * 8 != algorithm.block_size:
        raise ValueError("Invalid IV size ({0}) for {1}.".format(
            len(mode.initialization_vector), mode.name
        ))


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class CBC(object):
    name = "CBC"

    def __init__(self, initialization_vector):
        self.initialization_vector = initialization_vector

    validate_for_algorithm = _check_iv_length


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

    validate_for_algorithm = _check_iv_length


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class CFB(object):
    name = "CFB"

    def __init__(self, initialization_vector):
        self.initialization_vector = initialization_vector

    validate_for_algorithm = _check_iv_length


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class CFB8(object):
    name = "CFB8"

    def __init__(self, initialization_vector):
        self.initialization_vector = initialization_vector

    validate_for_algorithm = _check_iv_length


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithNonce)
class CTR(object):
    name = "CTR"

    def __init__(self, nonce):
        self.nonce = nonce

    def validate_for_algorithm(self, algorithm):
        if len(self.nonce) * 8 != algorithm.block_size:
            raise ValueError("Invalid nonce size ({0}) for {1}.".format(
                len(self.nonce), self.name
            ))


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
@utils.register_interface(interfaces.ModeWithAuthenticationTag)
class GCM(object):
    name = "GCM"

    def __init__(self, initialization_vector, tag=None, min_tag_length=16):
        # len(initialization_vector) must in [1, 2 ** 64), but it's impossible
        # to actually construct a bytes object that large, so we don't check
        # for it
        if min_tag_length < 4:
            raise ValueError("min_tag_length must be >= 4")
        if tag is not None and len(tag) < min_tag_length:
            raise ValueError(
                "Authentication tag must be {0} bytes or longer.".format(
                    min_tag_length)
            )

        self.initialization_vector = initialization_vector
        self.tag = tag

    def validate_for_algorithm(self, algorithm):
        pass
