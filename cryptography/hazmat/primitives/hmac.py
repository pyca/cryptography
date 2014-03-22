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

from cryptography import utils
from cryptography.exceptions import (
    AlreadyFinalized, InvalidSignature, UnsupportedAlgorithm
)
from cryptography.hazmat.backends.interfaces import HMACBackend
from cryptography.hazmat.primitives import constant_time, interfaces


@utils.register_interface(interfaces.HashContext)
class HMAC(object):
    def __init__(self, key, algorithm, backend, ctx=None):
        if not isinstance(backend, HMACBackend):
            raise UnsupportedAlgorithm(
                "Backend object does not implement HMACBackend")

        if not isinstance(algorithm, interfaces.HashAlgorithm):
            raise TypeError("Expected instance of interfaces.HashAlgorithm.")
        self.algorithm = algorithm

        self._backend = backend
        self._key = key
        if ctx is None:
            self._ctx = self._backend.create_hmac_ctx(key, self.algorithm)
        else:
            self._ctx = ctx

    def update(self, msg):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized")
        if isinstance(msg, six.text_type):
            raise TypeError("Unicode-objects must be encoded before hashing")
        self._ctx.update(msg)

    def copy(self):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized")
        return HMAC(
            self._key,
            self.algorithm,
            backend=self._backend,
            ctx=self._ctx.copy()
        )

    def finalize(self):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized")
        digest = self._ctx.finalize()
        self._ctx = None
        return digest

    def verify(self, signature):
        if isinstance(signature, six.text_type):
            raise TypeError("Unicode-objects must be encoded before verifying")
        digest = self.finalize()
        if not constant_time.bytes_eq(digest, signature):
            raise InvalidSignature("Signature did not match digest.")
