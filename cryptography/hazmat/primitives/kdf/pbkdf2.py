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

from cryptography.exceptions import InvalidKey, UnsupportedAlgorithm
from cryptography.hazmat.primitives import constant_time


class PBKDF2(object):
    def __init__(self, algorithm, length, salt, iterations, backend):
        if not backend.pbkdf2_hash_supported(algorithm):
            raise UnsupportedAlgorithm(
                "{0} is not supported by this backend".format(algorithm.name)
            )
        self.algorithm = algorithm
        if length > 2**31 - 1:
            raise ValueError("Requested length too large.")
        self._length = length
        # TODO: handle salt
        self._salt = salt
        self.iterations = iterations
        self._backend = backend

    def derive(self, key_material):
        return self._backend.derive_pbkdf2(
            self.algorithm,
            self._length,
            self._salt,
            self.iterations,
            key_material
        )

    def verify(self, key_material, expected_key):
        if not constant_time.bytes_eq(key_material, expected_key):
            raise InvalidKey("Signature did not match digest.")
