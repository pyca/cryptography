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

from cryptography.exceptions import InvalidToken, _Causes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import MD5, SHA1
from cryptography.hazmat.primitives.twofactor.hotp import HOTP

from ....utils import (
    load_nist_vectors, load_vectors_from_file, raises_unsupported
)

vectors = load_vectors_from_file(
    "twofactor/rfc-4226.txt", load_nist_vectors)


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.SHA1()),
    skip_message="Does not support HMAC-SHA1."
)
@pytest.mark.hmac
class TestHOTP(object):
    def test_invalid_key_length(self, backend):
        secret = os.urandom(10)

        with pytest.raises(ValueError):
            HOTP(secret, 6, SHA1(), backend)

    def test_invalid_hotp_length(self, backend):
        secret = os.urandom(16)

        with pytest.raises(ValueError):
            HOTP(secret, 4, SHA1(), backend)

    def test_invalid_algorithm(self, backend):
        secret = os.urandom(16)

        with pytest.raises(TypeError):
            HOTP(secret, 6, MD5(), backend)

    @pytest.mark.parametrize("params", vectors)
    def test_truncate(self, backend, params):
        secret = params["secret"]
        counter = int(params["counter"])
        truncated = params["truncated"]

        hotp = HOTP(secret, 6, SHA1(), backend)

        assert hotp._dynamic_truncate(counter) == int(truncated.decode(), 16)

    @pytest.mark.parametrize("params", vectors)
    def test_generate(self, backend, params):
        secret = params["secret"]
        counter = int(params["counter"])
        hotp_value = params["hotp"]

        hotp = HOTP(secret, 6, SHA1(), backend)

        assert hotp.generate(counter) == hotp_value

    @pytest.mark.parametrize("params", vectors)
    def test_verify(self, backend, params):
        secret = params["secret"]
        counter = int(params["counter"])
        hotp_value = params["hotp"]

        hotp = HOTP(secret, 6, SHA1(), backend)

        assert hotp.verify(hotp_value, counter) is None

    def test_invalid_verify(self, backend):
        secret = b"12345678901234567890"
        counter = 0

        hotp = HOTP(secret, 6, SHA1(), backend)

        with pytest.raises(InvalidToken):
            hotp.verify(b"123456", counter)

    def test_length_not_int(self, backend):
        secret = b"12345678901234567890"

        with pytest.raises(TypeError):
            HOTP(secret, b"foo", SHA1(), backend)


def test_invalid_backend():
    secret = b"12345678901234567890"

    pretend_backend = object()

    with raises_unsupported(_Causes.BACKEND_MISSING_INTERFACE):
        HOTP(secret, 8, hashes.SHA1(), pretend_backend)
