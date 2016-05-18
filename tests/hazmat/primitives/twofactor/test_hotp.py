# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

import pytest

from cryptography.exceptions import _Reasons
from cryptography.hazmat.backends.interfaces import HMACBackend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import MD5, SHA1
from cryptography.hazmat.primitives.twofactor import InvalidToken
from cryptography.hazmat.primitives.twofactor.hotp import HOTP

from ....utils import (
    load_nist_vectors, load_vectors_from_file, raises_unsupported_algorithm
)

vectors = load_vectors_from_file(
    "twofactor/rfc-4226.txt", load_nist_vectors)


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.SHA1()),
    skip_message="Does not support HMAC-SHA1."
)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
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

    def test_get_provisioning_uri(self, backend):
        secret = b"12345678901234567890"
        hotp = HOTP(secret, 6, SHA1(), backend)

        assert hotp.get_provisioning_uri("Alice Smith", 1, None) == (
            "otpauth://hotp/Alice%20Smith?digits=6&secret=GEZDGNBV"
            "GY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&counter=1")

        assert hotp.get_provisioning_uri("Alice Smith", 1, 'Foo') == (
            "otpauth://hotp/Foo:Alice%20Smith?digits=6&secret=GEZD"
            "GNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&issuer=Foo"
            "&counter=1")


def test_invalid_backend():
    secret = b"12345678901234567890"

    pretend_backend = object()

    with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
        HOTP(secret, 8, hashes.SHA1(), pretend_backend)
