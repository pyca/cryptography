# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import typing
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.twofactor import InvalidToken
from cryptography.hazmat.primitives.twofactor.totp import TOTP

from ....utils import load_nist_vectors, load_vectors_from_file

vectors = load_vectors_from_file("twofactor/rfc-6238.txt", load_nist_vectors)


class TestTOTP:
    @pytest.mark.parametrize(
        "params", [i for i in vectors if i["mode"] == b"SHA1"]
    )
    def test_generate_sha1(self, params):
        secret = params["secret"]
        time = int(params["time"])
        totp_value = params["totp"]

        totp = TOTP(secret, 8, hashes.SHA1(), 30)
        assert totp.generate(time) == totp_value

    @pytest.mark.parametrize(
        "params", [i for i in vectors if i["mode"] == b"SHA256"]
    )
    def test_generate_sha256(self, params):
        secret = params["secret"]
        time = int(params["time"])
        totp_value = params["totp"]

        totp = TOTP(secret, 8, hashes.SHA256(), 30)
        assert totp.generate(time) == totp_value

    @pytest.mark.parametrize(
        "params", [i for i in vectors if i["mode"] == b"SHA512"]
    )
    def test_generate_sha512(self, params):
        secret = params["secret"]
        time = int(params["time"])
        totp_value = params["totp"]

        totp = TOTP(secret, 8, hashes.SHA512(), 30)
        assert totp.generate(time) == totp_value

    @pytest.mark.parametrize(
        "params", [i for i in vectors if i["mode"] == b"SHA1"]
    )
    def test_verify_sha1(self, params):
        secret = params["secret"]
        time = int(params["time"])
        totp_value = params["totp"]

        totp = TOTP(secret, 8, hashes.SHA1(), 30)
        totp.verify(totp_value, time)

    @pytest.mark.parametrize(
        "params", [i for i in vectors if i["mode"] == b"SHA256"]
    )
    def test_verify_sha256(self, params):
        secret = params["secret"]
        time = int(params["time"])
        totp_value = params["totp"]

        totp = TOTP(secret, 8, hashes.SHA256(), 30)
        totp.verify(totp_value, time)

    @pytest.mark.parametrize(
        "params", [i for i in vectors if i["mode"] == b"SHA512"]
    )
    def test_verify_sha512(self, params):
        secret = params["secret"]
        time = int(params["time"])
        totp_value = params["totp"]

        totp = TOTP(secret, 8, hashes.SHA512(), 30)
        totp.verify(totp_value, time)

    def test_invalid_verify(self):
        secret = b"12345678901234567890"
        time = 59

        totp = TOTP(secret, 8, hashes.SHA1(), 30)

        with pytest.raises(InvalidToken):
            totp.verify(b"12345678", time)

    def test_floating_point_time_generate(self):
        secret = b"12345678901234567890"
        time = 59.1

        totp = TOTP(secret, 8, hashes.SHA1(), 30)

        assert totp.generate(time) == b"94287082"

    def test_get_provisioning_uri(self):
        secret = b"12345678901234567890"
        totp = TOTP(secret, 6, hashes.SHA1(), 30)

        assert totp.get_provisioning_uri("Alice Smith", None) == (
            "otpauth://totp/Alice%20Smith?digits=6&secret=GEZDGNBVG"
            "Y3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&period=30"
        )

        assert totp.get_provisioning_uri("Alice Smith", "World") == (
            "otpauth://totp/World:Alice%20Smith?digits=6&secret=GEZ"
            "DGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&issuer=World"
            "&period=30"
        )

    @pytest.mark.parametrize("issuer", [None, "", "Example/Inc"])
    @pytest.mark.parametrize(
        ("account_name", "encoded_account_name"),
        [
            ("alice", "alice"),
            ("alice/smith", "alice%2Fsmith"),
            ("alice%2Fsmith", "alice%252Fsmith"),
            ("Alïce / ?#&+%", "Al%C3%AFce%20%2F%20%3F%23%26%2B%25"),
        ],
    )
    def test_get_provisioning_uri_encodes_label(
        self, account_name, encoded_account_name, issuer
    ):
        totp = TOTP(b"12345678901234567890", 6, hashes.SHA1(), 30)
        uri = urlsplit(totp.get_provisioning_uri(account_name, issuer))

        prefix = "Example%2FInc:" if issuer else ""
        assert uri.path == f"/{prefix}{encoded_account_name}"
        label = f"{issuer}:{account_name}" if issuer else account_name
        assert unquote(uri.path[1:]) == label
        assert uri.fragment == ""
        parameters = parse_qs(uri.query, keep_blank_values=True)
        assert parameters["period"] == ["30"]
        if issuer is None:
            assert "issuer" not in parameters
        else:
            assert parameters["issuer"] == [issuer]

    def test_buffer_protocol(self):
        key = bytearray(b"a long key with lots of entropy goes here")
        totp = TOTP(key, 8, hashes.SHA512(), 30)
        time = 60
        assert totp.generate(time) == b"53049576"

    def test_invalid_time(self):
        key = b"12345678901234567890"
        totp = TOTP(key, 8, hashes.SHA1(), 30)

        with pytest.raises(TypeError):
            totp.generate(typing.cast(typing.Any, "test"))
