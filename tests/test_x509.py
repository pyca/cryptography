# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import datetime
import os
import textwrap

import pytest

from cryptography import x509
from cryptography.hazmat.backends.interfaces import RSABackend, X509Backend
from cryptography.hazmat.primitives import interfaces

from .hazmat.primitives.utils import load_vectors_from_file


def _der_to_pem(data):
    lines = textwrap.wrap(base64.b64encode(data), 64)
    return (
        "-----BEGIN CERTIFICATE-----\n" +
        "\n".join(lines) +
        "\n-----END CERTIFICATE-----"
    )


def _load_der_cert(name, backend):
    cert = load_vectors_from_file(
        os.path.join(
            "x509", "PKITS_data", "certs", name),
        lambda pemfile: x509.load_der_x509_certificate(
            pemfile.read(), backend
        )
    )
    return cert


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestX509Certificate(object):
    def test_load_good_ca_cert(self, backend):
        cert = _load_der_cert("GoodCACert.crt", backend)

        assert cert
        assert cert.not_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.serial == 2
        public_key = cert.public_key()
        assert isinstance(public_key, interfaces.RSAPublicKey)
        assert cert.version == x509.X509Version.v3

    def test_pre_2000_utc_not_before_cert(self, backend):
        cert = _load_der_cert(
            "Validpre2000UTCnotBeforeDateTest3EE.crt",
            backend
        )

        assert cert
        assert cert.not_before == datetime.datetime(1950, 1, 1, 12, 1)
        assert cert.not_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.version == x509.X509Version.v3

    def test_generalized_time_not_before_cert(self, backend):
        cert = _load_der_cert(
            "ValidGeneralizedTimenotBeforeDateTest4EE.crt",
            backend
        )

        assert cert
        assert cert.not_before == datetime.datetime(2002, 1, 1, 12, 1)
        assert cert.not_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.version == x509.X509Version.v3

    def test_generalized_time_not_after_cert(self, backend):
        cert = _load_der_cert(
            "ValidGeneralizedTimenotAfterDateTest8EE.crt",
            backend
        )
        assert cert
        assert cert.not_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_after == datetime.datetime(2050, 1, 1, 12, 1)
        assert cert.version == x509.X509Version.v3
