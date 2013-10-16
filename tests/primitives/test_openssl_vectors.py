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
Test using the OpenSSL Test Vectors
"""

from __future__ import absolute_import, division, print_function

import binascii

from cryptography.primitives.block import ciphers, modes

from .utils import generate_encrypt_test
from ..utils import load_openssl_vectors_from_file


class TestCamelliaCBC(object):
    test_OpenSSL = generate_encrypt_test(
        load_openssl_vectors_from_file,
        "Camellia",
        ["camellia-cbc.txt"],
        lambda key, iv: ciphers.Camellia(binascii.unhexlify(key)),
        lambda key, iv: modes.CBC(binascii.unhexlify(iv)),
        only_if=lambda api: api.supports_cipher("camellia-128-cbc"),
        skip_message="Does not support Camellia CBC",
    )


class TestCamelliaOFB(object):
    test_OpenSSL = generate_encrypt_test(
        load_openssl_vectors_from_file,
        "Camellia",
        ["camellia-ofb.txt"],
        lambda key, iv: ciphers.Camellia(binascii.unhexlify(key)),
        lambda key, iv: modes.OFB(binascii.unhexlify(iv)),
        only_if=lambda api: api.supports_cipher("camellia-128-ofb"),
        skip_message="Does not support Camellia OFB",
    )


class TestCamelliaCFB(object):
    test_OpenSSL = generate_encrypt_test(
        load_openssl_vectors_from_file,
        "Camellia",
        ["camellia-cfb.txt"],
        lambda key, iv: ciphers.Camellia(binascii.unhexlify(key)),
        lambda key, iv: modes.CFB(binascii.unhexlify(iv)),
        only_if=lambda api: api.supports_cipher("camellia-128-cfb"),
        skip_message="Does not support Camellia CFB",
    )


class TestAESCTR(object):
    test_OpenSSL = generate_encrypt_test(
        load_openssl_vectors_from_file,
        "AES",
        ["aes-128-ctr.txt", "aes-192-ctr.txt", "aes-256-ctr.txt"],
        lambda key, iv: ciphers.AES(binascii.unhexlify(key)),
        lambda key, iv: modes.CTR(binascii.unhexlify(iv)),
        only_if=lambda api: api.supports_cipher("aes-128-ctr"),
        skip_message="Does not support AES CTR",
    )
