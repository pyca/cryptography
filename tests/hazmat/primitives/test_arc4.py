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

import binascii
import os

import pytest

from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives.ciphers import algorithms

from .utils import generate_stream_encryption_test
from ...utils import load_nist_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.ARC4("\x00" * 16), None
    ),
    skip_message="Does not support ARC4",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestARC4(object):
    test_rfc = generate_stream_encryption_test(
        load_nist_vectors,
        os.path.join("ciphers", "ARC4"),
        [
            "rfc-6229-40.txt",
            "rfc-6229-56.txt",
            "rfc-6229-64.txt",
            "rfc-6229-80.txt",
            "rfc-6229-128.txt",
            "rfc-6229-192.txt",
            "rfc-6229-256.txt",
        ],
        lambda key, **kwargs: algorithms.ARC4(binascii.unhexlify(key)),
    )
