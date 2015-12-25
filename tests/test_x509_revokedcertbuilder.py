# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import datetime

import pytest

from cryptography import x509
from cryptography.hazmat.backends.interfaces import X509Backend


class TestRevokedCertificateBuilder(object):
    def test_serial_number_must_be_integer(self):
        with pytest.raises(TypeError):
            x509.RevokedCertificateBuilder().serial_number("notanx509name")

    def test_serial_number_must_be_non_negative(self):
        with pytest.raises(ValueError):
            x509.RevokedCertificateBuilder().serial_number(-1)

    def test_serial_number_must_be_less_than_160_bits_long(self):
        with pytest.raises(ValueError):
            # 2 raised to the 160th power is actually 161 bits
            x509.RevokedCertificateBuilder().serial_number(2 ** 160)

    def test_set_serial_number_twice(self):
        builder = x509.RevokedCertificateBuilder().serial_number(3)
        with pytest.raises(ValueError):
            builder.serial_number(4)

    def test_revocation_date_invalid(self):
        with pytest.raises(TypeError):
            x509.RevokedCertificateBuilder().revocation_date("notadatetime")

    def test_revocation_date_before_unix_epoch(self):
        with pytest.raises(ValueError):
            x509.RevokedCertificateBuilder().revocation_date(
                datetime.datetime(1960, 8, 10)
            )

    def test_set_revocation_date_twice(self):
        builder = x509.RevokedCertificateBuilder().revocation_date(
            datetime.datetime(2002, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.revocation_date(datetime.datetime(2002, 1, 1, 12, 1))

    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_serial_number(self, backend):
        builder = x509.RevokedCertificateBuilder().revocation_date(
            datetime.datetime(2002, 1, 1, 12, 1)
        )

        with pytest.raises(ValueError):
            builder.build(backend)

    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_revocation_date(self, backend):
        builder = x509.RevokedCertificateBuilder().serial_number(3)

        with pytest.raises(ValueError):
            builder.build(backend)

    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_create_revoked(self, backend):
        serial_number = 333
        revocation_date = datetime.datetime(2002, 1, 1, 12, 1)
        builder = x509.RevokedCertificateBuilder().serial_number(
            serial_number
        ).revocation_date(
            revocation_date
        )

        revoked_certificate = builder.build(backend)
        assert revoked_certificate.serial_number == serial_number
        assert revoked_certificate.revocation_date == revocation_date
        assert len(revoked_certificate.extensions) == 0
