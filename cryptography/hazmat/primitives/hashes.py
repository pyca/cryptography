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

import six

from cryptography.hazmat.primitives import interfaces


@interfaces.register(interfaces.HashContext)
class Hash(object):
    def __init__(self, algorithm, backend=None, ctx=None):
        if not isinstance(algorithm, interfaces.HashAlgorithm):
            raise TypeError("Expected instance of interfaces.HashAlgorithm.")
        self.algorithm = algorithm

        if backend is None:
            from cryptography.hazmat.bindings import _default_backend
            backend = _default_backend

        self._backend = backend

        if ctx is None:
            self._ctx = self._backend.hashes.create_ctx(self.algorithm)
        else:
            self._ctx = None

    def update(self, data):
        if isinstance(data, six.text_type):
            raise TypeError("Unicode-objects must be encoded before hashing")
        self._backend.hashes.update_ctx(self._ctx, data)

    def copy(self):
        return self.__class__(self.algorithm, backend=self._backend,
                              ctx=self._backend.hashes.copy_ctx(self._ctx))

    def finalize(self):
        return self._backend.hashes.finalize_ctx(self._ctx,
                                                 self.algorithm.digest_size)


@interfaces.register(interfaces.HashAlgorithm)
class SHA1(object):
    name = "sha1"
    digest_size = 20
    block_size = 64


@interfaces.register(interfaces.HashAlgorithm)
class SHA224(object):
    name = "sha224"
    digest_size = 28
    block_size = 64


@interfaces.register(interfaces.HashAlgorithm)
class SHA256(object):
    name = "sha256"
    digest_size = 32
    block_size = 64


@interfaces.register(interfaces.HashAlgorithm)
class SHA384(object):
    name = "sha384"
    digest_size = 48
    block_size = 128


@interfaces.register(interfaces.HashAlgorithm)
class SHA512(object):
    name = "sha512"
    digest_size = 64
    block_size = 128


@interfaces.register(interfaces.HashAlgorithm)
class RIPEMD160(object):
    name = "ripemd160"
    digest_size = 20
    block_size = 64


@interfaces.register(interfaces.HashAlgorithm)
class Whirlpool(object):
    name = "whirlpool"
    digest_size = 64
    block_size = 64


@interfaces.register(interfaces.HashAlgorithm)
class MD5(object):
    name = "md5"
    digest_size = 16
    block_size = 64
