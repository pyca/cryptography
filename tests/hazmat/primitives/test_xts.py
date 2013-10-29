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
import pytest

from cryptography.hazmat.primitives.ciphers import modes


class TestXTS(object):
    def test_xts_split_key(self):
        key1 = binascii.unhexlify(b"a650f2e235896ad144eef966ff00406e")
        key2 = binascii.unhexlify(b"156b537b7cd17a46551686f9561f3ddc")
        key = key1 + key2
        actual_key1, actual_key2 = modes.XTS.split_key(key)
        assert actual_key1 == key1
        assert actual_key2 == key2

    def test_xts_split_key_invalid_key_size(self):
        key = binascii.unhexlify(b"a650f2e235896ad144eef966ff00406eaa")
        with pytest.raises(ValueError):
            modes.XTS.split_key(key)
