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
from cryptography.exceptions import InvalidKey

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
        assert binascii.hexlify(scrypt.derive(password)) == derived_key

    @pytest.mark.parametrize("params", vectors)
    def test_verify(self, backend, params):
        password = params["password"]
        N = int(params["n"])
        r = int(params["r"])
        p = int(params["p"])
        length = int(params["length"])
        salt = params["salt"]
        derived_key = params["derived_key"]

        scrypt = Scrypt(salt, length, N, r, p, backend)
        assert scrypt.verify(password, binascii.unhexlify(derived_key)) is None

    def test_invalid_verify(self, backend):
        password = b"password"
        N = 1024
        r = 8
        p = 16
        length = 64
        salt = b"NaCl"
        derived_key = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e773"

        scrypt = Scrypt(salt, length, N, r, p, backend)
        with pytest.raises(InvalidKey):
            scrypt.verify(password, binascii.unhexlify(derived_key))
