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

from cryptography.hazmat.backends import openssl

_POTENTIAL_BACKENDS = ["openssl", "commoncrypto"]

_ALL_BACKENDS = []

for b in _POTENTIAL_BACKENDS:
    try:
        backend = __import__("cryptography.hazmat.backends.{0}".format(b),
                             fromlist=["backend"])
        _ALL_BACKENDS.append(backend.backend)
    except:
        pass


def default_backend():
    return openssl.backend
