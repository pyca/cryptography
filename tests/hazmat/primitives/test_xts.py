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

from cryptography.hazmat.primitives.block import ciphers, modes

from .utils import generate_encrypt_test
from ...utils import load_xts_vectors_from_file


class TestAES_XTS(object):
    test_KAT = generate_encrypt_test(
        lambda path: load_xts_vectors_from_file(path, "ENCRYPT"),
        os.path.join("AES", "XTSTestVectors", "tweak-128hexstr"),
        [
            "XTSGenAES128.rsp",
            "XTSGenAES256.rsp",
        ],
        lambda key, i, dataunitlen: ciphers.AES(binascii.unhexlify(key)),
        lambda key, i, dataunitlen: modes.XTS(binascii.unhexlify(i)),
    )
