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
from cryptography.exceptions import (
    InvalidSignature, UnsupportedAlgorithm, _Reasons
)
from cryptography.hazmat.primitives import constant_time, interfaces


@utils.register_interface(interfaces.MACContext)
@utils.register_interface(interfaces.HashContext)
class _HMACContext(object):
    def __init__(self, backend, key, algorithm, ctx=None):
        self._algorithm = algorithm
        self._backend = backend
        if ctx is None:
            ctx = self._backend._ffi.new("CCHmacContext *")
            try:
                alg = self._backend._supported_hmac_algorithms[algorithm.name]
            except KeyError:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported HMAC hash on this backend.".format(
                        algorithm.name),
                    _Reasons.UNSUPPORTED_HASH
                )

            self._backend._lib.CCHmacInit(ctx, alg, key, len(key))

        self._ctx = ctx
        self._key = key

    algorithm = utils.read_only_property("_algorithm")

    def copy(self):
        copied_ctx = self._backend._ffi.new("CCHmacContext *")
        # CommonCrypto has no APIs for copying HMACs, so we have to copy the
        # underlying struct.
        copied_ctx[0] = self._ctx[0]
        return _HMACContext(
            self._backend, self._key, self.algorithm, ctx=copied_ctx
        )

    def update(self, data):
        self._backend._lib.CCHmacUpdate(self._ctx, data, len(data))

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]",
                                     self.algorithm.digest_size)
        self._backend._lib.CCHmacFinal(self._ctx, buf)
        return self._backend._ffi.buffer(buf)[:]

    def verify(self, signature):
        digest = self.finalize()
        if not constant_time.bytes_eq(digest, signature):
            raise InvalidSignature("Signature did not match digest.")
