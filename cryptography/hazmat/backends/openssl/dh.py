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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import dh


class _DHKeyAgreementContext(object):
    def __init__(self, private_key, backend):
        self._private_key = private_key
        self._backend = backend

    def agree(self, public_key):
        lib = self._backend._lib
        ffi = self._backend._ffi

        key_size = lib.DH_size(private_key)

        buf = ffi.new("char[]", key_size)
        res = lib.DH_compute_key(
            key_buf, public_key, private_key
        )
        assert res != -1
        return ffi.buffer(buf)[:key_size]
