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

"""
Tests using the CRYPTREC (Camellia) Test Vectors
"""

from __future__ import absolute_import, division, print_function

import binascii

from cryptography.primitives.block import ciphers, modes

from .utils import generate_encrypt_test
from ..utils import load_cryptrec_vectors_from_file


class TestCamelliaECB(object):
    test_NTT = generate_encrypt_test(
        load_cryptrec_vectors_from_file,
        "Camellia",
        "NTT",
        ["camellia-128-ecb", "camellia-192-ecb", "camellia-256"],
        lambda key: ciphers.Camellia(binascii.unhexlify((key))),
        lambda key: modes.EBC(),
        only_if=lambda api: api.supports_cipher("camellia-128-ecb")
    )
