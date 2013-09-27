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

from cryptography.bindings.openssl.api import api


class TestOpenSSL(object):
    def test_api_exists(self):
        assert api

    def test_openssl_version_text(self):
        """
        This test checks the value of OPENSSL_VERSION_TEXT.

        Unfortunately, this define does not appear to have a
        formal content definition, so for now we'll test to see
        if it starts with OpenSSL as that appears to be true
        for every OpenSSL.
        """
        assert api.openssl_version_text().startswith("OpenSSL")

    def test_supports(self):
        assert api.supports("not-a-real-cipher") is False

    def test_create_block_cipher_context_with_unsupported_cipher(self):
        class FakeCipher(object):
            name = "FakeCipher"
            key_size = 24

        class FakeMode(object):
            name = "CCC"

        with pytest.raises(AssertionError):
            cipher = FakeCipher()
            mode = FakeMode()
            api.create_block_cipher_context(cipher, mode)
