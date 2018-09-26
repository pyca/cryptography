# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import os

import pytest

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from .test_x509 import _load_cert
from ..utils import load_vectors_from_file


def _load_data(filename, loader):
    return load_vectors_from_file(
        filename=filename,
        loader=lambda data: loader(data.read()),
        mode="rb"
    )


def _cert_and_issuer():
    from cryptography.hazmat.backends.openssl.backend import backend
    cert = _load_cert(
        os.path.join("x509", "cryptography.io.pem"),
        x509.load_pem_x509_certificate,
        backend
    )
    issuer = _load_cert(
        os.path.join("x509", "rapidssl_sha256_ca_g3.pem"),
        x509.load_pem_x509_certificate,
        backend
    )
    return cert, issuer


class TestOCSPRequest(object):
    def test_bad_request(self):
        with pytest.raises(ValueError):
            ocsp.load_der_ocsp_request(b"invalid")

    def test_load_request(self):
        req = _load_data(
            os.path.join("x509", "ocsp", "req-sha1.der"),
            ocsp.load_der_ocsp_request,
        )
        assert req.issuer_name_hash == (b"8\xcaF\x8c\x07D\x8d\xf4\x81\x96"
                                        b"\xc7mmLpQ\x9e`\xa7\xbd")
        assert req.issuer_key_hash == (b"yu\xbb\x84:\xcb,\xdez\t\xbe1"
                                       b"\x1bC\xbc\x1c*MSX")
        assert isinstance(req.hash_algorithm, hashes.SHA1)
        assert req.serial_number == int(
            "98D9E5C0B4C373552DF77C5D0F1EB5128E4945F9", 16
        )
        assert len(req.extensions) == 0

    def test_load_request_with_extensions(self):
        req = _load_data(
            os.path.join("x509", "ocsp", "req-ext-nonce.der"),
            ocsp.load_der_ocsp_request,
        )
        assert len(req.extensions) == 1
        ext = req.extensions[0]
        assert ext.critical is False
        assert ext.value == x509.OCSPNonce(
            b"\x04\x10{\x80Z\x1d7&\xb8\xb8OH\xd2\xf8\xbf\xd7-\xfd"
        )

    def test_load_request_two_requests(self):
        with pytest.raises(NotImplementedError):
            _load_data(
                os.path.join("x509", "ocsp", "req-multi-sha1.der"),
                ocsp.load_der_ocsp_request,
            )

    def test_invalid_hash_algorithm(self):
        req = _load_data(
            os.path.join("x509", "ocsp", "req-invalid-hash-alg.der"),
            ocsp.load_der_ocsp_request,
        )
        with pytest.raises(UnsupportedAlgorithm):
            req.hash_algorithm

    def test_serialize_request(self):
        req_bytes = load_vectors_from_file(
            filename=os.path.join("x509", "ocsp", "req-sha1.der"),
            loader=lambda data: data.read(),
            mode="rb"
        )
        req = ocsp.load_der_ocsp_request(req_bytes)
        assert req.public_bytes(serialization.Encoding.DER) == req_bytes

    def test_invalid_serialize_encoding(self):
        req = _load_data(
            os.path.join("x509", "ocsp", "req-sha1.der"),
            ocsp.load_der_ocsp_request,
        )
        with pytest.raises(ValueError):
            req.public_bytes("invalid")
        with pytest.raises(ValueError):
            req.public_bytes(serialization.Encoding.PEM)


class TestOCSPRequestBuilder(object):
    def test_add_two_certs(self):
        cert, issuer = _cert_and_issuer()
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA1())
        with pytest.raises(ValueError):
            builder.add_certificate(cert, issuer, hashes.SHA1())

    def test_create_ocsp_request_no_req(self):
        builder = ocsp.OCSPRequestBuilder()
        with pytest.raises(ValueError):
            builder.build()

    def test_create_ocsp_request_invalid_alg(self):
        cert, issuer = _cert_and_issuer()
        builder = ocsp.OCSPRequestBuilder()
        with pytest.raises(ValueError):
            builder.add_certificate(cert, issuer, hashes.MD5())

    def test_create_ocsp_request_invalid_cert(self):
        cert, issuer = _cert_and_issuer()
        builder = ocsp.OCSPRequestBuilder()
        with pytest.raises(TypeError):
            builder.add_certificate(b"notacert", issuer, hashes.SHA1())

        with pytest.raises(TypeError):
            builder.add_certificate(cert, b"notacert", hashes.SHA1())

    def test_create_ocsp_request(self):
        cert, issuer = _cert_and_issuer()
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA1())
        req = builder.build()
        serialized = req.public_bytes(serialization.Encoding.DER)
        assert serialized == base64.b64decode(
            b"MEMwQTA/MD0wOzAJBgUrDgMCGgUABBRAC0Z68eay0wmDug1gfn5ZN0gkxAQUw5zz"
            b"/NNGCDS7zkZ/oHxb8+IIy1kCAj8g"
        )
