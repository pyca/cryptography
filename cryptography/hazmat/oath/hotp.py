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

import struct

from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.hashes import SHA1


class HOTP(object):
    def __init__(self, secret, length, backend):
        self.secret = secret
        self.length = length
        self.backend = backend

    def generate(self, counter):
        sbit = self._dynamic_truncate(counter)
        return str(sbit % (10**self.length)).zfill(self.length)

    def verify(self, hotp, counter):
        return constant_time.bytes_eq(self.generate(counter), hotp)

    def _dynamic_truncate(self, counter):
        ctx = self.backend.create_hmac_ctx(self.secret, SHA1)
        ctx.update(struct.pack(">Q", counter))
        hmac_value = ctx.finalize()

        offset_bits = ord(hmac_value[19]) & 0b1111
        offset = int(offset_bits)
        P = hmac_value[offset:offset+4]
        return struct.unpack(">I", P)[0] & 0x7fffffff
