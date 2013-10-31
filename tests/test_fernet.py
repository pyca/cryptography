import base64
import calendar
import json
import os

import iso8601

import pytest

import six

from cryptography.fernet import Fernet, InvalidToken


def json_parametrize(keys, fname):
    path = os.path.join(os.path.dirname(__file__), "vectors", "fernet", fname)
    with open(path) as f:
        data = json.load(f)
    return pytest.mark.parametrize(keys, [
        tuple([entry[k] for k in keys])
        for entry in data
    ])


class TestFernet(object):
    @json_parametrize(
        ("secret", "now", "iv", "src", "token"), "generate.json",
    )
    def test_generate(self, secret, now, iv, src, token):
        f = Fernet(base64.urlsafe_b64decode(secret.encode("ascii")))
        actual_token = f._encrypt_from_parts(
            src.encode("ascii"),
            calendar.timegm(iso8601.parse_date(now).utctimetuple()),
            b"".join(map(six.int2byte, iv))
        )
        assert actual_token == token

    @json_parametrize(
        ("secret", "now", "src", "ttl_sec", "token"), "verify.json",
    )
    def test_verify(self, secret, now, src, ttl_sec, token):
        f = Fernet(base64.urlsafe_b64decode(secret.encode("ascii")))
        payload = f.decrypt(
            token.encode("ascii"),
            ttl=ttl_sec,
            current_time=calendar.timegm(iso8601.parse_date(now).utctimetuple())
        )
        assert payload == src

    @json_parametrize(("secret", "token", "now", "ttl_sec"), "invalid.json")
    def test_invalid(self, secret, token, now, ttl_sec):
        f = Fernet(base64.urlsafe_b64decode(secret.encode("ascii")))
        with pytest.raises(InvalidToken):
            f.decrypt(
                token.encode("ascii"),
                ttl=ttl_sec,
                current_time=calendar.timegm(iso8601.parse_date(now).utctimetuple())
            )

    def test_unicode(self):
        f = Fernet(b"\x00" * 32)
        with pytest.raises(TypeError):
            f.encrypt(six.u(""))
        with pytest.raises(TypeError):
            f.decrypt(six.u(""))
