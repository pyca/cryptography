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

import pytest

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.multibackend import PrioritizedMultiBackend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class DummyCipherBackend(object):
    def __init__(self, supported_ciphers):
        self._ciphers = supported_ciphers

    def cipher_supported(self, algorithm, mode):
        return (type(algorithm), type(mode)) in self._ciphers

    def create_symmetric_encryption_ctx(self, algorithm, mode):
        if not self.cipher_supported(algorithm, mode):
            raise UnsupportedAlgorithm

    def create_symmetric_decryption_ctx(self, algorithm, mode):
        if not self.cipher_supported(algorithm, mode):
            raise UnsupportedAlgorithm


class DummyHashBackend(object):
    def __init__(self, supported_algorithms):
        self._algorithms = supported_algorithms

    def hash_supported(self, algorithm):
        return type(algorithm) in self._algorithms

    def create_hash_ctx(self, algorithm):
        if not self.hash_supported(algorithm):
            raise UnsupportedAlgorithm



class TestPrioritizedMultiBackend(object):
    def test_ciphers(self):
        backend = PrioritizedMultiBackend([
            DummyCipherBackend([
                (algorithms.AES, modes.CBC),
            ])
        ])
        assert backend.cipher_supported(
            algorithms.AES(b"\x00" * 16), modes.CBC(b"\x00" * 16)
        )

        cipher = Cipher(
            algorithms.AES(b"\x00" * 16),
            modes.CBC(b"\x00" * 16),
            backend=backend
        )
        cipher.encryptor()
        cipher.decryptor()

        cipher = Cipher(
            algorithms.Camellia(b"\x00" * 16),
            modes.CBC(b"\x00" * 16),
            backend=backend
        )
        with pytest.raises(UnsupportedAlgorithm):
            cipher.encryptor()
        with pytest.raises(UnsupportedAlgorithm):
            cipher.decryptor()

    def test_hashes(self):
        backend = PrioritizedMultiBackend([
            DummyHashBackend([hashes.MD5])
        ])
        assert backend.hash_supported(hashes.MD5())

        hashes.Hash(hashes.MD5(), backend=backend)

        with pytest.raises(UnsupportedAlgorithm):
            hashes.Hash(hashes.SHA1(), backend=backend)
