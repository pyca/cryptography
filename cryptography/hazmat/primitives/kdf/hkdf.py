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

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import constant_time

def hkdf_derive(input_key, key_length, salt, info, hash, backend):
    if hash is None:
        hash = hashes.SHA256()

    if info is None:
        info = b""

    if salt is None:
        salt = b"\x00" * (hash.digest_size // 8)

    h = hmac.HMAC(salt, hash, backend=backend)
    h.update(input_key)
    PRK = h.finalize()

    output = [b'']
    counter = 1

    while (hash.digest_size // 8) * len(output) < key_length:
        h = hmac.HMAC(PRK, hash, backend=backend)
        h.update(output[-1])
        h.update(info)
        h.update(chr(counter))
        output.append(h.finalize())
        counter += 1

    return b"".join(output)[:key_length]


def hkdf_verify(expected, input_key, key_length, salt, info, hash, backend):
    derived = hkdf_derive(input_key, key_length, salt=salt, info=info,
                           hash=hash, backend=backend)

    if not constant_time.bytes_eq(expected, derived):
        raise ValueError("")

