# -*- coding: utf-8 -*-
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography import x509


def test_object_identier_constructor(benchmark):
    benchmark(x509.ObjectIdentifier, "1.3.6.1.4.1.11129.2.4.5")


def test_aki_public_bytes(benchmark):
    aki = x509.AuthorityKeyIdentifier(
        key_identifier=b"\x00" * 16,
        authority_cert_issuer=None,
        authority_cert_serial_number=None,
    )
    benchmark(aki.public_bytes)
