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

import binascii

import six


class HMAC(object):
    def __init__(self, key, hash_cls, data=None, ctx=None, backend=None):
        super(HMAC, self).__init__()
        if backend is None:
            from cryptography.hazmat.bindings import _default_backend
            backend = _default_backend
        self._backend = backend
        self.hash_cls = hash_cls
        self.key = key
        if ctx is None:
            self._ctx = self._backend.hmacs.create_ctx(key, self.hash_cls)
        else:
            self._ctx = ctx

        if data is not None:
            self.update(data)

    def update(self, data):
        if isinstance(data, six.text_type):
            raise TypeError("Unicode-objects must be encoded before hashing")
        self._backend.hmacs.update_ctx(self._ctx, data)

    def copy(self):
        return self.__class__(self.key, hash_cls=self.hash_cls,
                              backend=self._backend, ctx=self._copy_ctx())

    def digest(self):
        return self._backend.hmacs.finalize_ctx(self._copy_ctx(),
                                                self.hash_cls.digest_size)

    def hexdigest(self):
        return str(binascii.hexlify(self.digest()).decode("ascii"))

    def _copy_ctx(self):
        return self._backend.hmacs.copy_ctx(self._ctx)
