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

import six

from cryptography.hazmat.primitives import hmac


def hkdf_extract(algorithm, ikm, salt, backend):
    h = hmac.HMAC(salt, algorithm, backend=backend)
    h.update(ikm)
    return h.finalize()


def hkdf_expand(algorithm, prk, info, length, backend):
    output = [b'']
    counter = 1

    while (algorithm.digest_size // 8) * len(output) < length:
        h = hmac.HMAC(prk, algorithm, backend=backend)
        h.update(output[-1])
        h.update(info)
        h.update(six.int2byte(counter))
        output.append(h.finalize())
        counter += 1

    return b"".join(output)[:length]


def hkdf_derive(key, length, salt, info, algorithm, backend):
    if info is None:
        info = b""

    if salt is None:
        salt = b"\x00" * (algorithm.digest_size // 8)

    return hkdf_expand(
        algorithm,
        hkdf_extract(algorithm, key, salt, backend=backend),
        info,
        length,
        backend=backend
    )
