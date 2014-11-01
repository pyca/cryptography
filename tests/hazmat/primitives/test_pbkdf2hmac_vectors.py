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

import pytest

from cryptography.hazmat.backends.interfaces import PBKDF2HMACBackend
from cryptography.hazmat.primitives import hashes

from .utils import generate_pbkdf2_test
from ...utils import load_nist_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.pbkdf2_hmac_supported(hashes.SHA1()),
    skip_message="Does not support SHA1 for PBKDF2HMAC",
)
@pytest.mark.requires_backend_interface(interface=PBKDF2HMACBackend)
class TestPBKDF2HMACSHA1(object):
    test_pbkdf2_sha1 = generate_pbkdf2_test(
        load_nist_vectors,
        "KDF",
        [
            "rfc-6070-PBKDF2-SHA1.txt",
        ],
        hashes.SHA1(),
    )
