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

import sys

import cffi

from cryptography.hazmat.bindings.utils import _create_modulename

TYPES = """
uint8_t Cryptography_constant_time_bytes_eq(uint8_t *, size_t, uint8_t *,
                                            size_t);
"""

FUNCTIONS = """
uint8_t Cryptography_constant_time_bytes_eq(uint8_t *a, size_t len_a,
                                            uint8_t *b, size_t len_b) {
    size_t i = 0;
    uint8_t mismatch = 0;
    if (len_a != len_b) {
        return 0;
    }
    for (i = 0; i < len_a; i++) {
        mismatch |= a[i] ^ b[i];
    }

    /* Make sure any bits set are copied to the lowest bit */
    mismatch |= mismatch >> 4;
    mismatch |= mismatch >> 2;
    mismatch |= mismatch >> 1;
    /* Now check the low bit to see if it's set */
    return (mismatch & 1) == 0;
}
"""

_ffi = cffi.FFI()
_ffi.cdef(TYPES)
_lib = _ffi.verify(
    source=FUNCTIONS,
    modulename=_create_modulename([TYPES], FUNCTIONS, sys.version),
    ext_package="cryptography",
)


def bytes_eq(a, b):
    if not isinstance(a, bytes) or not isinstance(b, bytes):
            raise TypeError("a and b must be bytes.")

    return _lib.Cryptography_constant_time_bytes_eq(a, len(a), b, len(b)) == 1
