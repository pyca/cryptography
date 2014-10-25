# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import hmac
import os

from cryptography.hazmat.bindings.utils import build_ffi


with open(os.path.join(os.path.dirname(__file__), "src/constant_time.h")) as f:
    TYPES = f.read()

with open(os.path.join(os.path.dirname(__file__), "src/constant_time.c")) as f:
    FUNCTIONS = f.read()


_ffi, _lib = build_ffi(
    cdef_source=TYPES,
    verify_source=FUNCTIONS,
)

if hasattr(hmac, "compare_digest"):
    def bytes_eq(a, b):
        if not isinstance(a, bytes) or not isinstance(b, bytes):
            raise TypeError("a and b must be bytes.")

        return hmac.compare_digest(a, b)

else:
    def bytes_eq(a, b):
        if not isinstance(a, bytes) or not isinstance(b, bytes):
            raise TypeError("a and b must be bytes.")

        return _lib.Cryptography_constant_time_bytes_eq(
            a, len(a), b, len(b)
        ) == 1
