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

import struct

import six

from cryptography.exceptions import InvalidToken, UnsupportedAlgorithm, _Causes
from cryptography.hazmat.backends.interfaces import HMACBackend
from cryptography.hazmat.primitives import constant_time, hmac
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA512


class HOTP(object):
    def __init__(self, key, length, algorithm, backend):
        if not isinstance(backend, HMACBackend):
            raise UnsupportedAlgorithm(
                "Backend object does not implement HMACBackend",
                _Causes.BACKEND_MISSING_INTERFACE
            )

        if len(key) < 16:
            raise ValueError("Key length has to be at least 128 bits.")

        if not isinstance(length, six.integer_types):
            raise TypeError("Length parameter must be an integer type")

        if length < 6 or length > 8:
            raise ValueError("Length of HOTP has to be between 6 to 8.")

        if not isinstance(algorithm, (SHA1, SHA256, SHA512)):
            raise TypeError("Algorithm must be SHA1, SHA256 or SHA512")

        self._key = key
        self._length = length
        self._algorithm = algorithm
        self._backend = backend

    def generate(self, counter):
        truncated_value = self._dynamic_truncate(counter)
        hotp = truncated_value % (10 ** self._length)
        return "{0:0{1}}".format(hotp, self._length).encode()

    def verify(self, hotp, counter):
        if not constant_time.bytes_eq(self.generate(counter), hotp):
            raise InvalidToken("Supplied HOTP value does not match")

    def _dynamic_truncate(self, counter):
        ctx = hmac.HMAC(self._key, self._algorithm, self._backend)
        ctx.update(struct.pack(">Q", counter))
        hmac_value = ctx.finalize()

        offset_bits = six.indexbytes(hmac_value, len(hmac_value) - 1) & 0b1111

        offset = int(offset_bits)
        p = hmac_value[offset:offset + 4]
        return struct.unpack(">I", p)[0] & 0x7fffffff
