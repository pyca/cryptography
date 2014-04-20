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

import six

from cryptography import utils
from cryptography.exceptions import (
    AlreadyFinalized, InvalidKey, _Reasons
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, interfaces
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ...utils import raises_unsupported_algorithm


@utils.register_interface(interfaces.HashAlgorithm)
class DummyHash(object):
    name = "dummy-hash"


class TestPBKDF2HMAC(object):
    def test_already_finalized(self):
        kdf = PBKDF2HMAC(hashes.SHA1(), 20, b"salt", 10, default_backend())
        kdf.derive(b"password")
        with pytest.raises(AlreadyFinalized):
            kdf.derive(b"password2")

        kdf = PBKDF2HMAC(hashes.SHA1(), 20, b"salt", 10, default_backend())
        key = kdf.derive(b"password")
        with pytest.raises(AlreadyFinalized):
            kdf.verify(b"password", key)

        kdf = PBKDF2HMAC(hashes.SHA1(), 20, b"salt", 10, default_backend())
        kdf.verify(b"password", key)
        with pytest.raises(AlreadyFinalized):
            kdf.verify(b"password", key)

    def test_unsupported_algorithm(self):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            PBKDF2HMAC(DummyHash(), 20, b"salt", 10, default_backend())

    def test_invalid_key(self):
        kdf = PBKDF2HMAC(hashes.SHA1(), 20, b"salt", 10, default_backend())
        key = kdf.derive(b"password")

        kdf = PBKDF2HMAC(hashes.SHA1(), 20, b"salt", 10, default_backend())
        with pytest.raises(InvalidKey):
            kdf.verify(b"password2", key)

    def test_unicode_error_with_salt(self):
        with pytest.raises(TypeError):
            PBKDF2HMAC(hashes.SHA1(), 20, six.u("salt"), 10, default_backend())

    def test_unicode_error_with_key_material(self):
        kdf = PBKDF2HMAC(hashes.SHA1(), 20, b"salt", 10, default_backend())
        with pytest.raises(TypeError):
            kdf.derive(six.u("unicode here"))


def test_invalid_backend():
    pretend_backend = object()

    with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
        PBKDF2HMAC(hashes.SHA1(), 20, b"salt", 10, pretend_backend)
