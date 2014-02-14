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
from cryptography.hazmat.backends.multibackend import MultiBackend
from cryptography.hazmat.bindings.commoncrypto.binding import (
    Binding as CommonCryptoBinding
)

_ALL_BACKENDS = [openssl.backend]

if CommonCryptoBinding.is_available():
    from cryptography.hazmat.backends import commoncrypto
    _ALL_BACKENDS.append(commoncrypto.backend)


_default_backend = MultiBackend(_ALL_BACKENDS)


def default_backend():
    return _default_backend
