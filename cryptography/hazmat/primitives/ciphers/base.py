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
from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.primitives import interfaces


class Cipher(object):
    def __init__(self, algorithm, mode, backend=None):
        if backend is None:
            from cryptography.hazmat.bindings import (
                _default_backend as backend,
            )

        if not isinstance(algorithm, interfaces.CipherAlgorithm):
            raise TypeError("Expected interface of interfaces.CipherAlgorithm")

        if mode is not None:
            mode.validate_for_algorithm(algorithm)

        self.algorithm = algorithm
        self.mode = mode
        self._backend = backend

    def encryptor(self):
        return _CipherContext(self._backend.create_symmetric_encryption_ctx(
            self.algorithm, self.mode
        ))

    def decryptor(self):
        return _CipherContext(self._backend.create_symmetric_decryption_ctx(
            self.algorithm, self.mode
        ))


@utils.register_interface(interfaces.CipherContext)
class _CipherContext(object):
    def __init__(self, ctx):
        self._ctx = ctx

    def update(self, data):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized")
        return self._ctx.update(data)

    def finalize(self):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized")
        data = self._ctx.finalize()
        self._ctx = None
        return data
