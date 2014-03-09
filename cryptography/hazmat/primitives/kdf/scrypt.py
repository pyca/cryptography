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

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import interfaces, constant_time
from cryptography import utils


@utils.register_interface(interfaces.KeyDerivationFunction)
class Scrypt(object):
    def __init__(self, salt, length, N, r, p, backend):
        self._backend = backend
        self._salt = salt
        self._length = length
        self._N = N
        self._r = r
        self._p = p

    def derive(self, key_material):
        return self._backend.derive_scrypt(
            key_material, self._salt, self._length, self._N, self._r, self._p)

    def verify(self, key_material, expected_key):
        derived_key = self.derive(key_material)
        if not constant_time.bytes_eq(derived_key, expected_key):
            raise InvalidKey("Keys do not match.")
