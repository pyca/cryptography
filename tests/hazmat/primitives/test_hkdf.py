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

from cryptography.exceptions import (
    AlreadyFinalized, InvalidKey, UnsupportedAlgorithm
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@pytest.mark.hmac
class TestHKDF(object):
    def test_length_limit(self, backend):
        big_length = 255 * (hashes.SHA256().digest_size // 8) + 1

        with pytest.raises(ValueError):
            HKDF(
                hashes.SHA256(),
                big_length,
                salt=None,
                info=None,
                backend=backend
            )

    def test_already_finalized(self, backend):
        hkdf = HKDF(
            hashes.SHA256(),
            16,
            salt=None,
            info=None,
            backend=backend
        )

        hkdf.derive(b"\x01" * 16)

        with pytest.raises(AlreadyFinalized):
            hkdf.derive(b"\x02" * 16)

        hkdf = HKDF(
            hashes.SHA256(),
            16,
            salt=None,
            info=None,
            backend=backend
        )

        hkdf.verify(b"\x01" * 16, b"gJ\xfb{\xb1Oi\xc5sMC\xb7\xe4@\xf7u")

        with pytest.raises(AlreadyFinalized):
            hkdf.verify(b"\x02" * 16, b"gJ\xfb{\xb1Oi\xc5sMC\xb7\xe4@\xf7u")

        hkdf = HKDF(
            hashes.SHA256(),
            16,
            salt=None,
            info=None,
            backend=backend
        )

    def test_verify(self, backend):
        hkdf = HKDF(
            hashes.SHA256(),
            16,
            salt=None,
            info=None,
            backend=backend
        )

        hkdf.verify(b"\x01" * 16, b"gJ\xfb{\xb1Oi\xc5sMC\xb7\xe4@\xf7u")

    def test_verify_invalid(self, backend):
        hkdf = HKDF(
            hashes.SHA256(),
            16,
            salt=None,
            info=None,
            backend=backend
        )

        with pytest.raises(InvalidKey):
            hkdf.verify(b"\x02" * 16, b"gJ\xfb{\xb1Oi\xc5sMC\xb7\xe4@\xf7u")

    def test_unicode_typeerror(self, backend):
        with pytest.raises(TypeError):
            HKDF(
                hashes.SHA256(),
                16,
                salt=six.u("foo"),
                info=None,
                backend=backend
            )

        with pytest.raises(TypeError):
            HKDF(
                hashes.SHA256(),
                16,
                salt=None,
                info=six.u("foo"),
                backend=backend
            )

        with pytest.raises(TypeError):
            hkdf = HKDF(
                hashes.SHA256(),
                16,
                salt=None,
                info=None,
                backend=backend
            )

            hkdf.derive(six.u("foo"))

        with pytest.raises(TypeError):
            hkdf = HKDF(
                hashes.SHA256(),
                16,
                salt=None,
                info=None,
                backend=backend
            )

            hkdf.verify(six.u("foo"), b"bar")

        with pytest.raises(TypeError):
            hkdf = HKDF(
                hashes.SHA256(),
                16,
                salt=None,
                info=None,
                backend=backend
            )

            hkdf.verify(b"foo", six.u("bar"))


def test_invalid_backend():
    pretend_backend = object()

    with pytest.raises(UnsupportedAlgorithm):
        HKDF(hashes.SHA256(), 16, None, None, pretend_backend)
