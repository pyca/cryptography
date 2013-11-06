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

from cryptography.hazmat.primitives.ciphers import algorithms, modes

from .utils import generate_encrypt_test
from ...utils import load_nist_vectors_from_file


class TestCAST5(object):
    test_ECB = generate_encrypt_test(
        lambda path: load_nist_vectors_from_file(path, "ENCRYPT"),
        os.path.join("ciphers", "CAST5"),
        [
            "cast5-ecb.txt",
        ],
        lambda key: algorithms.CAST5(binascii.unhexlify((key))),
        lambda key: modes.ECB(),
        only_if=lambda backend: backend.ciphers.supported(
            algorithms.CAST5("\x00" * 16), modes.ECB()
        ),
        skip_message="Does not support CAST5 ECB",
    )
