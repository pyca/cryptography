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

import cffi

header = "#include <openssl/opensslconf.h>"
isdefined_template = """
uint8_t Cryptography_is_defined_{0}() {{
#ifdef {0}
    return 1;
#else
    return 0;
#endif
}}
"""

ffi = cffi.FFI()
defines = ["OPENSSL_EXPORT_VAR_AS_FUNCTION", "OPENSSL_THREADS"]
source = []

for define in defines:
    func_name = "Cryptography_is_defined_{0}".format(define)
    ffi.cdef("uint8_t {0}();".format(func_name))
    source.append(isdefined_template.format(define))

lib = ffi.verify(source=header + "\n" + "\n".join(source))


def is_defined(define):
    func_name = "Cryptography_is_defined_{0}".format(define)
    return getattr(lib, func_name)()
