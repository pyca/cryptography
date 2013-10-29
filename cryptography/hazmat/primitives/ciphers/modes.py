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
@utils.register_interface(interfaces.ModeWithTweak)
class XTS(object):
    name = "XTS"
    _key_sizes = frozenset([256, 512])

    def __init__(self, tweak, additional_key_data=None):
        super(XTS, self).__init__()
        self.tweak = tweak
        self.additional_key_data = additional_key_data

    @classmethod
    def split_key(self, key):
        keylen = len(key)
        if keylen * 8 not in self._key_sizes:
            raise ValueError("Invalid key size ({0}) for {1}".format(
                keylen * 8, self.name
            ))
        return (key[:keylen//2], key[keylen//2:])
