# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

import pytest

from cryptography import x509
from cryptography.exceptions import _Reasons
from cryptography.hazmat.primitives.serialization import pkcs7

from .utils import load_vectors_from_file
from ...utils import raises_unsupported_algorithm


class TestPKCS7Loading(object):
    def test_load_invalid_der_pkcs7(self):
        with pytest.raises(ValueError):
            pkcs7.load_der_pkcs7_certificates(b"nonsense")

    def test_load_invalid_pem_pkcs7(self):
        with pytest.raises(ValueError):
            pkcs7.load_pem_pkcs7_certificates(b"nonsense")

    def test_not_bytes_der(self):
        with pytest.raises(TypeError):
            pkcs7.load_der_pkcs7_certificates(38)

    def test_not_bytes_pem(self):
        with pytest.raises(TypeError):
            pkcs7.load_pem_pkcs7_certificates(38)

    def test_load_pkcs7_pem(self):
        certs = load_vectors_from_file(
            os.path.join("pkcs7", "isrg.pem"),
            lambda pemfile: pkcs7.load_pem_pkcs7_certificates(pemfile.read()),
            mode="rb",
        )
        assert len(certs) == 1
        assert certs[0].subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        ) == [
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"ISRG Root X1")
        ]

    def test_load_pkcs7_der(self):
        certs = load_vectors_from_file(
            os.path.join("pkcs7", "amazon-roots.p7b"),
            lambda derfile: pkcs7.load_der_pkcs7_certificates(derfile.read()),
            mode="rb",
        )
        assert len(certs) == 2
        assert certs[0].subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        ) == [
            x509.NameAttribute(
                x509.oid.NameOID.COMMON_NAME, u"Amazon Root CA 3"
            )
        ]
        assert certs[1].subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        ) == [
            x509.NameAttribute(
                x509.oid.NameOID.COMMON_NAME, u"Amazon Root CA 2"
            )
        ]

    def test_load_pkcs7_unsupported_type(self):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_SERIALIZATION):
            load_vectors_from_file(
                os.path.join("pkcs7", "enveloped.pem"),
                lambda pemfile: pkcs7.load_pem_pkcs7_certificates(
                    pemfile.read()
                ),
                mode="rb",
            )
