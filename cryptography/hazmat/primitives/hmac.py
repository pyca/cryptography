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
class HMAC(object):
    def __init__(self, key, algorithm, ctx=None, backend=None):
        super(HMAC, self).__init__()
        if not isinstance(algorithm, interfaces.HashAlgorithm):
            raise TypeError("Expected instance of interfaces.HashAlgorithm.")
        self.algorithm = algorithm

        if backend is None:
            from cryptography.hazmat.bindings import _default_backend
            backend = _default_backend

        self._backend = backend
        self._key = key
        if ctx is None:
            self._ctx = self._backend.hmacs.create_ctx(key, self.algorithm)
        else:
            self._ctx = ctx

    def update(self, msg):
        if isinstance(msg, six.text_type):
            raise TypeError("Unicode-objects must be encoded before hashing")
        self._ctx.update(msg)

    def copy(self):
        return HMAC(
            self._key, self.algorithm, ctx=self._ctx.copy(),
            backend=self._backend
        )

    def finalize(self):
        return self._ctx.finalize()
