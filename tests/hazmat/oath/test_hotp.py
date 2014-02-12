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

import pytest
from cryptography.hazmat.oath.hotp import HOTP
from tests.utils import load_vectors_from_file, load_nist_vectors

vectors = load_vectors_from_file(
    "oath/rfc-4226.txt", load_nist_vectors)


@pytest.mark.oath
class TestHOTP(object):

    @pytest.mark.parametrize("params", vectors)
    def test_truncate(self, backend, params):
        secret = params["secret"]
        counter = int(params["counter"])
        truncated = params["truncated"]

        hotp = HOTP(secret, 6, backend)

        assert hex(hotp._dynamic_truncate(counter))[2:] == truncated.decode()

    @pytest.mark.parametrize("params", vectors)
    def test_generate(self, backend, params):
        secret = params["secret"]
        counter = int(params["counter"])
        hotp_value = params["hotp"]

        hotp = HOTP(secret, 6, backend)

        assert hotp.generate(counter) == hotp_value

    @pytest.mark.parametrize("params", vectors)
    def test_verify(self, backend, params):
        secret = params["secret"]
        counter = int(params["counter"])
        hotp_value = params["hotp"]

        hotp = HOTP(secret, 6, backend)

        assert hotp.verify(hotp_value, counter) is True
