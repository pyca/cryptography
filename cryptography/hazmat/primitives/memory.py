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

import contextlib
import sys

import cffi

import six

from cryptography.hazmat.bindings.utils import _create_modulename

TYPES = """
int Cryptography_secure_wipe(uint8_t *, size_t);
"""

FUNCTIONS = """
/* Based on OPENSSL_cleanse */
uint8_t cleanse_ctr = 0;
int Cryptography_secure_wipe(uint8_t *ptr, size_t len) {
    unsigned char *p = ptr;
    size_t loop = len;
    size_t ctr = cleanse_ctr;

    if (ptr == NULL) {
        return -1;
    }

    while(loop--) {
        *(p++) = (unsigned char)ctr;
        ctr += (17 + ((size_t)p & 0xF));
    }

    p = memchr(ptr, (unsigned char)ctr, len);

    if(p) {
        ctr += (63 + (size_t)p);
    }

    cleanse_ctr = (unsigned char)ctr;

    return 0;
}
"""

_ffi = cffi.FFI()
_ffi.cdef(TYPES)
_lib = _ffi.verify(
    source=FUNCTIONS,
    modulename=_create_modulename([TYPES], FUNCTIONS, sys.version),
    ext_package="cryptography",
)


@contextlib.contextmanager
def secure_wipe(data):
    yield
    res = _lib.Cryptography_secure_wipe(data, len(data))
    assert res == 0
