# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import calendar
import json
import os
import time

import iso8601

import pytest

import six

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import CipherBackend, HMACBackend
from cryptography.hazmat.primitives.ciphers import algorithms, modes

import cryptography_vectors


def json_parametrize(keys, filename):
    vector_file = cryptography_vectors.open_vector_file(
        os.path.join('fernet', filename), "r"
    )
    with vector_file:
        data = json.load(vector_file)
        return pytest.mark.parametrize(keys, [
            tuple([entry[k] for k in keys])
            for entry in data
        ])


def test_default_backend():
    f = Fernet(Fernet.generate_key())
    assert f._backend is default_backend()


@pytest.mark.requires_backend_interface(interface=CipherBackend)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES(b"\x00" * 32), modes.CBC(b"\x00" * 16)
    ),
    skip_message="Does not support AES CBC",
)
class TestFernet(object):
    @json_parametrize(
        ("secret", "now", "iv", "src", "token"), "generate.json",
    )
    def test_generate(self, secret, now, iv, src, token, backend):
        f = Fernet(secret.encode("ascii"), backend=backend)
        actual_token = f._encrypt_from_parts(
            src.encode("ascii"),
            calendar.timegm(iso8601.parse_date(now).utctimetuple()),
            b"".join(map(six.int2byte, iv))
        )
        assert actual_token == token.encode("ascii")

    @json_parametrize(
        ("secret", "now", "src", "ttl_sec", "token"), "verify.json",
    )
    def test_verify(self, secret, now, src, ttl_sec, token, backend,
                    monkeypatch):
        f = Fernet(secret.encode("ascii"), backend=backend)
        current_time = calendar.timegm(iso8601.parse_date(now).utctimetuple())
        monkeypatch.setattr(time, "time", lambda: current_time)
        payload = f.decrypt(token.encode("ascii"), ttl=ttl_sec)
        assert payload == src.encode("ascii")

    @json_parametrize(("secret", "token", "now", "ttl_sec"), "invalid.json")
    def test_invalid(self, secret, token, now, ttl_sec, backend, monkeypatch):
        f = Fernet(secret.encode("ascii"), backend=backend)
        current_time = calendar.timegm(iso8601.parse_date(now).utctimetuple())
        monkeypatch.setattr(time, "time", lambda: current_time)
        with pytest.raises(InvalidToken):
            f.decrypt(token.encode("ascii"), ttl=ttl_sec)

    def test_invalid_start_byte(self, backend):
        f = Fernet(base64.urlsafe_b64encode(b"\x00" * 32), backend=backend)
        with pytest.raises(InvalidToken):
            f.decrypt(base64.urlsafe_b64encode(b"\x81"))

    def test_timestamp_too_short(self, backend):
        f = Fernet(base64.urlsafe_b64encode(b"\x00" * 32), backend=backend)
        with pytest.raises(InvalidToken):
            f.decrypt(base64.urlsafe_b64encode(b"\x80abc"))

    def test_non_base64_token(self, backend):
        f = Fernet(base64.urlsafe_b64encode(b"\x00" * 32), backend=backend)
        with pytest.raises(InvalidToken):
            f.decrypt(b"\x00")

    def test_unicode(self, backend):
        f = Fernet(base64.urlsafe_b64encode(b"\x00" * 32), backend=backend)
        with pytest.raises(TypeError):
            f.encrypt(u"")
        with pytest.raises(TypeError):
            f.decrypt(u"")

    def test_timestamp_ignored_no_ttl(self, monkeypatch, backend):
        f = Fernet(base64.urlsafe_b64encode(b"\x00" * 32), backend=backend)
        pt = b"encrypt me"
        token = f.encrypt(pt)
        ts = "1985-10-26T01:20:01-07:00"
        current_time = calendar.timegm(iso8601.parse_date(ts).utctimetuple())
        monkeypatch.setattr(time, "time", lambda: current_time)
        assert f.decrypt(token, ttl=None) == pt

    @pytest.mark.parametrize("message", [b"", b"Abc!", b"\x00\xFF\x00\x80"])
    def test_roundtrips(self, message, backend):
        f = Fernet(Fernet.generate_key(), backend=backend)
        assert f.decrypt(f.encrypt(message)) == message

    def test_bad_key(self, backend):
        with pytest.raises(ValueError):
            Fernet(base64.urlsafe_b64encode(b"abc"), backend=backend)


@pytest.mark.requires_backend_interface(interface=CipherBackend)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES(b"\x00" * 32), modes.CBC(b"\x00" * 16)
    ),
    skip_message="Does not support AES CBC",
)
class TestMultiFernet(object):
    def test_encrypt(self, backend):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32), backend=backend)
        f2 = Fernet(base64.urlsafe_b64encode(b"\x01" * 32), backend=backend)
        f = MultiFernet([f1, f2])

        assert f1.decrypt(f.encrypt(b"abc")) == b"abc"

    def test_decrypt(self, backend):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32), backend=backend)
        f2 = Fernet(base64.urlsafe_b64encode(b"\x01" * 32), backend=backend)
        f = MultiFernet([f1, f2])

        assert f.decrypt(f1.encrypt(b"abc")) == b"abc"
        assert f.decrypt(f2.encrypt(b"abc")) == b"abc"

        with pytest.raises(InvalidToken):
            f.decrypt(b"\x00" * 16)

    def test_no_fernets(self, backend):
        with pytest.raises(ValueError):
            MultiFernet([])

    def test_non_iterable_argument(self, backend):
        with pytest.raises(TypeError):
            MultiFernet(None)
