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
Test using the CRYPTREC (Camellia) Test Vectors
"""

from __future__ import absolute_import, division, print_function

import binascii
import itertools
import os

import pytest

from cryptography.bindings.openssl.api import api
from cryptography.primitives.block import BlockCipher, ciphers, modes

from ..utils import load_cryptrec_vectors_from_file

CAMELLIA_ECB_SUPPORTED = api.supports('camellia-128-ecb')


def parameterize_encrypt_test(cipher, vector_type, params, fnames):
    return pytest.mark.parametrize(params,
        list(itertools.chain.from_iterable(
            load_cryptrec_vectors_from_file(
                os.path.join(cipher, vector_type, fname),
            )
            for fname in fnames
        ))
    )


@pytest.mark.skipif("not CAMELLIA_ECB_SUPPORTED")
class TestCamelliaECB(object):

    @parameterize_encrypt_test(
        "Camellia", "NTT",
        ("key", "plaintext", "ciphertext"),
        [
            "camellia-128-ecb.txt",
            "camellia-192-ecb.txt",
            "camellia-256-ecb.txt",
        ]
    )
    def test_NTT(self, key, plaintext, ciphertext):
        cipher = BlockCipher(
            ciphers.Camellia(binascii.unhexlify(key)),
            modes.ECB(),
        )
        actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
        actual_ciphertext += cipher.finalize()
        assert binascii.hexlify(actual_ciphertext).upper() == ciphertext
