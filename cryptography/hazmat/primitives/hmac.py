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
    def __init__(self, key, msg=None, digestmod=None, ctx=None, backend=None):
        super(HMAC, self).__init__()
        if backend is None:
            from cryptography.hazmat.bindings import _default_backend
            backend = _default_backend

        if digestmod is None:
            raise TypeError("digestmod is a required argument")

        self._backend = backend
        self.digestmod = digestmod
        self.key = key
        if ctx is None:
            self._ctx = self._backend.hmacs.create_ctx(key, self.digestmod)
        else:
            self._ctx = ctx

        if msg is not None:
            self.update(msg)

    def update(self, msg):
        if isinstance(msg, six.text_type):
            raise TypeError("Unicode-objects must be encoded before hashing")
        self._backend.hmacs.update_ctx(self._ctx, msg)

    def copy(self):
        return self.__class__(self.key, digestmod=self.digestmod,
                              backend=self._backend, ctx=self._copy_ctx())

    def digest(self):
        return self._backend.hmacs.finalize_ctx(self._copy_ctx(),
                                                self.digestmod.digest_size)

    def hexdigest(self):
        return str(binascii.hexlify(self.digest()).decode("ascii"))

    def _copy_ctx(self):
        return self._backend.hmacs.copy_ctx(self._ctx)
