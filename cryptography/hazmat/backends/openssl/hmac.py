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
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import interfaces


@utils.register_interface(interfaces.MACContext)
@utils.register_interface(interfaces.HashContext)
class _HMACContext(object):
    def __init__(self, backend, key, algorithm, ctx=None):
        self._algorithm = algorithm
        self._backend = backend

        if ctx is None:
            ctx = self._backend._ffi.new("HMAC_CTX *")
            self._backend._lib.HMAC_CTX_init(ctx)
            ctx = self._backend._ffi.gc(
                ctx, self._backend._lib.HMAC_CTX_cleanup
            )
            evp_md = self._backend._lib.EVP_get_digestbyname(
                algorithm.name.encode('ascii'))
            if evp_md == self._backend._ffi.NULL:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported hash on this backend.".format(
                        algorithm.name),
                    _Reasons.UNSUPPORTED_HASH
                )
            res = self._backend._lib.Cryptography_HMAC_Init_ex(
                ctx, key, len(key), evp_md, self._backend._ffi.NULL
            )
            assert res != 0

        self._ctx = ctx
        self._key = key

    algorithm = utils.read_only_property("_algorithm")

    def copy(self):
        copied_ctx = self._backend._ffi.new("HMAC_CTX *")
        self._backend._lib.HMAC_CTX_init(copied_ctx)
        copied_ctx = self._backend._ffi.gc(
            copied_ctx, self._backend._lib.HMAC_CTX_cleanup
        )
        res = self._backend._lib.Cryptography_HMAC_CTX_copy(
            copied_ctx, self._ctx
        )
        assert res != 0
        return _HMACContext(
            self._backend, self._key, self.algorithm, ctx=copied_ctx
        )

    def update(self, data):
        res = self._backend._lib.Cryptography_HMAC_Update(
            self._ctx, data, len(data)
        )
        assert res != 0

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]",
                                     self._backend._lib.EVP_MAX_MD_SIZE)
        outlen = self._backend._ffi.new("unsigned int *")
        res = self._backend._lib.Cryptography_HMAC_Final(
            self._ctx, buf, outlen
        )
        assert res != 0
        assert outlen[0] == self.algorithm.digest_size
        self._backend._lib.HMAC_CTX_cleanup(self._ctx)
        return self._backend._ffi.buffer(buf)[:outlen[0]]
