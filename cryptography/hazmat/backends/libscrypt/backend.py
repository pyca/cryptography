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

from cryptography.hazmat.backends.interfaces import ScryptBackend
from cryptography import utils
from cryptography.hazmat.bindings.libscrypt.binding import Binding


@utils.register_interface(ScryptBackend)
class Backend(object):
    """
    libscrypt API wrapper.
    """
    name = "libscrypt"

    def __init__(self):
        self._binding = Binding()
        self._ffi = self._binding.ffi
        self._lib = self._binding.lib

    def derive_scrypt(self, key_material, salt, length, N, r, p):
        buf = self._ffi.new("uint8_t[]", length)
        self._lib.libscrypt_scrypt(key_material, len(key_material),
                                   salt, len(salt), N, r, p, buf, length)
        return self._ffi.buffer(buf)[:]

backend = Backend()
