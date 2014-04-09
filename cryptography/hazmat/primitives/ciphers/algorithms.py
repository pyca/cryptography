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


def _verify_key_size(algorithm, key):
    # Verify that the key size matches the expected key size
    if len(key) * 8 not in algorithm.key_sizes:
        raise ValueError("Invalid key size ({0}) for {1}".format(
            len(key) * 8, algorithm.name
        ))
    return key


@utils.register_interface(interfaces.BlockCipherAlgorithm)
@utils.register_interface(interfaces.CipherAlgorithm)
class AES(object):
    name = "AES"
    block_size = 128
    key_sizes = frozenset([128, 192, 256])

    def __init__(self, key):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self):
        return len(self.key) * 8


@utils.register_interface(interfaces.BlockCipherAlgorithm)
@utils.register_interface(interfaces.CipherAlgorithm)
class Camellia(object):
    name = "camellia"
    block_size = 128
    key_sizes = frozenset([128, 192, 256])

    def __init__(self, key):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self):
        return len(self.key) * 8


@utils.register_interface(interfaces.BlockCipherAlgorithm)
@utils.register_interface(interfaces.CipherAlgorithm)
class TripleDES(object):
    name = "3DES"
    block_size = 64
    key_sizes = frozenset([64, 128, 192])

    def __init__(self, key):
        if len(key) == 8:
            key += key + key
        elif len(key) == 16:
            key += key[:8]
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self):
        return len(self.key) * 8


@utils.register_interface(interfaces.BlockCipherAlgorithm)
@utils.register_interface(interfaces.CipherAlgorithm)
class Blowfish(object):
    name = "Blowfish"
    block_size = 64
    key_sizes = frozenset(range(32, 449, 8))

    def __init__(self, key):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self):
        return len(self.key) * 8


@utils.register_interface(interfaces.BlockCipherAlgorithm)
@utils.register_interface(interfaces.CipherAlgorithm)
class CAST5(object):
    name = "CAST5"
    block_size = 64
    key_sizes = frozenset(range(40, 129, 8))

    def __init__(self, key):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self):
        return len(self.key) * 8


@utils.register_interface(interfaces.CipherAlgorithm)
class ARC4(object):
    name = "RC4"
    key_sizes = frozenset([40, 56, 64, 80, 128, 192, 256])

    def __init__(self, key):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self):
        return len(self.key) * 8


@utils.register_interface(interfaces.CipherAlgorithm)
class IDEA(object):
    name = "IDEA"
    block_size = 64
    key_sizes = frozenset([128])

    def __init__(self, key):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self):
        return len(self.key) * 8


@utils.register_interface(interfaces.BlockCipherAlgorithm)
@utils.register_interface(interfaces.CipherAlgorithm)
class SEED(object):
    name = "SEED"
    block_size = 128
    key_sizes = frozenset([128])

    def __init__(self, key):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self):
        return len(self.key) * 8
