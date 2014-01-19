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

from collections import namedtuple

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.interfaces import (
    HashBackend,
)
from cryptography.hazmat.bindings.commoncrypto.binding import Binding
from cryptography.hazmat.primitives import interfaces


@utils.register_interface(HashBackend)
class Backend(object):
    """
    CommonCrypto API wrapper.
    """
    name = "commoncrypto"
    HashMethods = namedtuple(
        "HashMethods", ["ctx", "hash_init", "hash_update", "hash_final"]
    )

    def __init__(self):
        self._binding = Binding()
        self._ffi = self._binding.ffi
        self._lib = self._binding.lib

        self.hash_mapping = {
            "md5": self.HashMethods(
                "CC_MD5_CTX *", self._lib.CC_MD5_Init,
                self._lib.CC_MD5_Update, self._lib.CC_MD5_Final
            ),
            "sha1": self.HashMethods(
                "CC_SHA1_CTX *", self._lib.CC_SHA1_Init,
                self._lib.CC_SHA1_Update, self._lib.CC_SHA1_Final
            ),
            "sha224": self.HashMethods(
                "CC_SHA256_CTX *", self._lib.CC_SHA224_Init,
                self._lib.CC_SHA224_Update, self._lib.CC_SHA224_Final
            ),
            "sha256": self.HashMethods(
                "CC_SHA256_CTX *", self._lib.CC_SHA256_Init,
                self._lib.CC_SHA256_Update, self._lib.CC_SHA256_Final
            ),
            "sha384": self.HashMethods(
                "CC_SHA512_CTX *", self._lib.CC_SHA384_Init,
                self._lib.CC_SHA384_Update, self._lib.CC_SHA384_Final
            ),
            "sha512": self.HashMethods(
                "CC_SHA512_CTX *", self._lib.CC_SHA512_Init,
                self._lib.CC_SHA512_Update, self._lib.CC_SHA512_Final
            ),
        }

    def hash_supported(self, algorithm):
        try:
            self.hash_mapping[algorithm.name]
            return True
        except KeyError:
            return False

    def create_hash_ctx(self, algorithm):
        return _HashContext(self, algorithm)


@utils.register_interface(interfaces.HashContext)
class _HashContext(object):
    def __init__(self, backend, algorithm, ctx=None):
        self.algorithm = algorithm
        self._backend = backend

        if ctx is None:
            try:
                methods = self._backend.hash_mapping[self.algorithm.name]
            except KeyError:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported hash on this backend".format(
                        algorithm.name)
                )
            ctx = self._backend._ffi.new(methods.ctx)
            res = methods.hash_init(ctx)
            assert res == 1

        self._ctx = ctx

    def copy(self):
        methods = self._backend.hash_mapping[self.algorithm.name]
        new_ctx = self._backend._ffi.new(methods.ctx)
        # CommonCrypto has no APIs for copying hashes, so we have to copy the
        # underlying struct.
        new_ctx[0] = self._ctx[0]

        return _HashContext(self._backend, self.algorithm, ctx=new_ctx)

    def update(self, data):
        methods = self._backend.hash_mapping[self.algorithm.name]
        res = methods.hash_update(self._ctx, data, len(data))
        assert res == 1

    def finalize(self):
        methods = self._backend.hash_mapping[self.algorithm.name]
        buf = self._backend._ffi.new("unsigned char[]",
                                     self.algorithm.digest_size)
        res = methods.hash_final(buf, self._ctx)
        assert res == 1
        return self._backend._ffi.buffer(buf)[:]


backend = Backend()
