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


@utils.register_interface(interfaces.Mode)
class ECB(object):
    name = "ECB"


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class OFB(object):
    name = "OFB"

    def __init__(self, initialization_vector):
        self.initialization_vector = initialization_vector


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class CFB(object):
    name = "CFB"

    def __init__(self, initialization_vector):
        self.initialization_vector = initialization_vector


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithNonce)
class CTR(object):
    name = "CTR"

    def __init__(self, nonce):
        self.nonce = nonce


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
@utils.register_interface(interfaces.ModeWithAuthenticationTag)
class GCM(object):
    name = "GCM"

    def __init__(self, initialization_vector, tag=None):
        if tag is not None and len(tag) < 4:
            raise ValueError(
                "Authentication tag must be 4 bytes or longer"
            )

        self.initialization_vector = initialization_vector
        self.tag = tag
