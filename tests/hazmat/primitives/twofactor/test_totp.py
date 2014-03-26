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

from cryptography.exceptions import InvalidToken, _Causes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.twofactor.totp import TOTP

from ....utils import (
    load_nist_vectors, load_vectors_from_file, raises_unsupported
)

vectors = load_vectors_from_file(
    "twofactor/rfc-6238.txt", load_nist_vectors)


@pytest.mark.hmac
class TestTOTP(object):
    @pytest.mark.supported(
        only_if=lambda backend: backend.hmac_supported(hashes.SHA1()),
        skip_message="Does not support HMAC-SHA1."
    )
    @pytest.mark.parametrize(
        "params", [i for i in vectors if i["mode"] == b"SHA1"])
    def test_generate_sha1(self, backend, params):
        secret = params["secret"]
        time = int(params["time"])
        totp_value = params["totp"]

        totp = TOTP(secret, 8, hashes.SHA1(), 30, backend)
        assert totp.generate(time) == totp_value

    @pytest.mark.supported(
        only_if=lambda backend: backend.hmac_supported(hashes.SHA256()),
        skip_message="Does not support HMAC-SHA256."
    )
    @pytest.mark.parametrize(
        "params", [i for i in vectors if i["mode"] == b"SHA256"])
    def test_generate_sha256(self, backend, params):
        secret = params["secret"]
        time = int(params["time"])
        totp_value = params["totp"]

        totp = TOTP(secret, 8, hashes.SHA256(), 30, backend)
        assert totp.generate(time) == totp_value

    @pytest.mark.supported(
        only_if=lambda backend: backend.hmac_supported(hashes.SHA512()),
        skip_message="Does not support HMAC-SHA512."
    )
    @pytest.mark.parametrize(
        "params", [i for i in vectors if i["mode"] == b"SHA512"])
    def test_generate_sha512(self, backend, params):
        secret = params["secret"]
        time = int(params["time"])
        totp_value = params["totp"]

        totp = TOTP(secret, 8, hashes.SHA512(), 30, backend)
        assert totp.generate(time) == totp_value

    @pytest.mark.supported(
        only_if=lambda backend: backend.hmac_supported(hashes.SHA1()),
        skip_message="Does not support HMAC-SHA1."
    )
    @pytest.mark.parametrize(
        "params", [i for i in vectors if i["mode"] == b"SHA1"])
    def test_verify_sha1(self, backend, params):
        secret = params["secret"]
        time = int(params["time"])
        totp_value = params["totp"]

        totp = TOTP(secret, 8, hashes.SHA1(), 30, backend)

        assert totp.verify(totp_value, time) is None

    @pytest.mark.supported(
        only_if=lambda backend: backend.hmac_supported(hashes.SHA256()),
        skip_message="Does not support HMAC-SHA256."
    )
    @pytest.mark.parametrize(
        "params", [i for i in vectors if i["mode"] == b"SHA256"])
    def test_verify_sha256(self, backend, params):
        secret = params["secret"]
        time = int(params["time"])
        totp_value = params["totp"]

        totp = TOTP(secret, 8, hashes.SHA256(), 30, backend)

        assert totp.verify(totp_value, time) is None

    @pytest.mark.supported(
        only_if=lambda backend: backend.hmac_supported(hashes.SHA512()),
        skip_message="Does not support HMAC-SHA512."
    )
    @pytest.mark.parametrize(
        "params", [i for i in vectors if i["mode"] == b"SHA512"])
    def test_verify_sha512(self, backend, params):
        secret = params["secret"]
        time = int(params["time"])
        totp_value = params["totp"]

        totp = TOTP(secret, 8, hashes.SHA512(), 30, backend)

        assert totp.verify(totp_value, time) is None

    def test_invalid_verify(self, backend):
        secret = b"12345678901234567890"
        time = 59

        totp = TOTP(secret, 8, hashes.SHA1(), 30, backend)

        with pytest.raises(InvalidToken):
            totp.verify(b"12345678", time)

    def test_floating_point_time_generate(self, backend):
        secret = b"12345678901234567890"
        time = 59.1

        totp = TOTP(secret, 8, hashes.SHA1(), 30, backend)

        assert totp.generate(time) == b"94287082"


def test_invalid_backend():
    secret = b"12345678901234567890"

    pretend_backend = object()

    with raises_unsupported(_Causes.BACKEND_MISSING_INTERFACE):
        TOTP(secret, 8, hashes.SHA1(), 30, pretend_backend)
