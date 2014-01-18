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

import os

import pytest

from cryptography.exceptions import UnsupportedAlgorithm

from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.pkcs1 import (
    PKCS1PublicKey,
    PKCS1PrivateKey
)

from cryptography.hazmat.pkcs8 import (
    PKCS8PublicKey,
    PKCS8PrivateKey
)


from cryptography.hazmat.primitives.ciphers import algorithms, modes

_pem_vector_root = os.path.join(
    os.path.dirname(__file__), "vectors", "pkcs", "pem-keys",
)

_rsa_pem_private_keys = [
    "certificate-transparency/test-embedded-key.pem",
    "certificate-transparency/test-embedded-with-intermediate-key.pem",
    "certificate-transparency/test-embedded-with-intermediate-preca-key.pem",
    "certificate-transparency/test-embedded-with-preca-key.pem",
    "certificate-transparency/test-intermediate-key.pem",
    "certificate-transparency/test-key.pem",
]

_ec_pem_private_keys = [
    "certificate-transparency/ct-server-key.pem"
]

_encrypted_pkcs8_pem_private_keys = [
    "certificate-transparency/ca-key.pem",
    "certificate-transparency/ca-pre-key.pem",
    "certificate-transparency/intermediate-key.pem",
    "certificate-transparency/intermediate-pre-key.pem"
]


def _load_pem_file(name):
    return open(os.path.join(
        _pem_vector_root, name
    )).read()


@pytest.fixture(params=_rsa_pem_private_keys)
def rsa_pem_private_key(request):
    return _load_pem_file(request.param)


def test_pkcs1_pem_rsa_private_key(backend, rsa_pem_private_key):
    pkcs1 = PKCS1PrivateKey(backend)
    key = pkcs1.load_pem(rsa_pem_private_key, None)
    assert key and isinstance(key, rsa.RSAPrivateKey)

    pem = pkcs1.dump_pem(key, None, None, None)
    assert pem.strip() == rsa_pem_private_key.strip()

    AES128 = algorithms.AES(b"\x00"*16)
    password = b"this is not an aes key"
    enc_pem = pkcs1.dump_pem(key, AES128, modes.CBC(None), password)
    assert enc_pem != pem

    key = pkcs1.load_pem(enc_pem, password)
    assert key and isinstance(key, rsa.RSAPrivateKey)


def test_invalid_pkcs1_header(backend):
    pkcs1 = PKCS1PrivateKey(backend)

    with pytest.raises(ValueError):
        pkcs1.load_pem(_load_pem_file("invalid-header.pem"), None)


def test_corrupted_pkcs1_data(backend):
    pkcs1 = PKCS1PrivateKey(backend)

    with pytest.raises(ValueError):
        pkcs1.load_pem(_load_pem_file("corrupt-data.pem"), None)


def test_pkc1_unable_to_decrypt(backend):
    pkcs1 = PKCS1PrivateKey(backend)

    with pytest.raises(ValueError):
        pkcs1.load_pem(_load_pem_file("enc-test-key-BADGER.pem"), None)

    with pytest.raises(ValueError):
        pkcs1.load_pem(_load_pem_file("enc-test-key-BADGER.pem"), b"")

    with pytest.raises(ValueError):
        pkcs1.load_pem(_load_pem_file("enc-test-key-BADGER.pem"), b"WRONG")
