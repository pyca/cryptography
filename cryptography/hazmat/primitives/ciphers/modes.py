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

from cryptography.hazmat.primitives import interfaces


@interfaces.register(interfaces.Mode)
@interfaces.register(interfaces.ModeWithInitializationVector)
class CBC(object):
    name = "CBC"

    def __init__(self, initialization_vector):
        super(CBC, self).__init__()
        self.initialization_vector = initialization_vector


@interfaces.register(interfaces.Mode)
class ECB(object):
    name = "ECB"


@interfaces.register(interfaces.Mode)
@interfaces.register(interfaces.ModeWithInitializationVector)
class OFB(object):
    name = "OFB"

    def __init__(self, initialization_vector):
        super(OFB, self).__init__()
        self.initialization_vector = initialization_vector


@interfaces.register(interfaces.Mode)
@interfaces.register(interfaces.ModeWithInitializationVector)
class CFB(object):
    name = "CFB"

    def __init__(self, initialization_vector):
        super(CFB, self).__init__()
        self.initialization_vector = initialization_vector


@interfaces.register(interfaces.Mode)
@interfaces.register(interfaces.ModeWithNonce)
class CTR(object):
    name = "CTR"

    def __init__(self, nonce):
        super(CTR, self).__init__()
        self.nonce = nonce
