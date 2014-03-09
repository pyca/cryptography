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

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from tests.utils import load_vectors_from_file, load_nist_vectors

vectors = load_vectors_from_file(
    "KDF/scrypt.txt", load_nist_vectors)


@pytest.mark.scrypt
class TestScrypt(object):
    @pytest.mark.parametrize("params", vectors)
    def test_derive(self, backend, params):
        password = params["password"]
        N = int(params["n"])
        r = int(params["r"])
        p = int(params["p"])
        length = int(params["length"])
        salt = params["salt"]
        derived_key = params["derived_key"]

        scrypt = Scrypt(salt, length, N, r, p, backend)
        assert scrypt.derive(password).encode("hex_codec") == derived_key
