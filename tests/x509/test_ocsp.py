# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import datetime
import os

import pytest

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
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

    def test_add_extension_twice(self):
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_extension(x509.OCSPNonce(b"123"), False)
        with pytest.raises(ValueError):
            builder.add_extension(x509.OCSPNonce(b"123"), False)

    def test_add_invalid_extension(self):
        builder = ocsp.OCSPRequestBuilder()
        with pytest.raises(TypeError):
            builder.add_extension("notanext", False)

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

    @pytest.mark.parametrize(
        ("ext", "critical"),
        [
            [x509.OCSPNonce(b"0000"), False],
            [x509.OCSPNonce(b"\x00\x01\x02"), True],
        ]
    )
    def test_create_ocsp_request_with_extension(self, ext, critical):
        cert, issuer = _cert_and_issuer()
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(
            cert, issuer, hashes.SHA1()
        ).add_extension(
            ext, critical
        )
        req = builder.build()
        assert len(req.extensions) == 1
        assert req.extensions[0].value == ext
        assert req.extensions[0].oid == ext.oid
        assert req.extensions[0].critical is critical


class TestOCSPResponse(object):
    def test_bad_response(self):
        with pytest.raises(ValueError):
            ocsp.load_der_ocsp_response(b"invalid")

    def test_load_response(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-sha256.der"),
            ocsp.load_der_ocsp_response,
        )
        from cryptography.hazmat.backends.openssl.backend import backend
        issuer = _load_cert(
            os.path.join("x509", "letsencryptx3.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert (resp.signature_algorithm_oid ==
                x509.SignatureAlgorithmOID.RSA_WITH_SHA256)
        assert resp.signature == base64.b64decode(
            b"I9KUlyLV/2LbNCVu1BQphxdNlU/jBzXsPYVscPjW5E93pCrSO84GkIWoOJtqsnt"
            b"78DLcQPnF3W24NXGzSGKlSWfXIsyoXCxnBm0mIbD5ZMnKyXEnqSR33Z9He/A+ML"
            b"A8gbrDUipGNPosesenkKUnOtFIzEGv29hV5E6AMP2ORPVsVlTAZegPJFbbVIWc0"
            b"rZGFCXKxijDxtUtgWzBhpBAI50JbPHi+IVuaOe4aDJLYgZ0BIBNa6bDI+rScyoy"
            b"5U0DToV7SZn6CoJ3U19X7BHdYn6TLX0xi43eXuzBGzdHnSzmsc7r/DvkAKJm3vb"
            b"dVECXqe/gFlXJUBcZ25jhs70MUA=="
        )
        assert resp.tbs_response_bytes == base64.b64decode(
            b"MIHWoUwwSjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzA"
            b"hBgNVBAMTGkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzGA8yMDE4MDgzMDExMT"
            b"UwMFowdTBzMEswCQYFKw4DAhoFAAQUfuZq53Kas/z4oiBkbBahLWBxCF0EFKhKa"
            b"mMEfd265tE5t6ZFZe/zqOyhAhIDHHh6fckClQB7xfIiCztSevCAABgPMjAxODA4"
            b"MzAxMTAwMDBaoBEYDzIwMTgwOTA2MTEwMDAwWg=="
        )
        issuer.public_key().verify(
            resp.signature,
            resp.tbs_response_bytes,
            PKCS1v15(),
            hashes.SHA256()
        )
        assert resp.certificates == []
        assert resp.responder_key_hash is None
        assert resp.responder_name == issuer.subject
        assert resp.produced_at == datetime.datetime(2018, 8, 30, 11, 15)
        assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD
        assert resp.revocation_time is None
        assert resp.revocation_reason is None
        assert resp.this_update == datetime.datetime(2018, 8, 30, 11, 0)
        assert resp.next_update == datetime.datetime(2018, 9, 6, 11, 0)
        assert resp.issuer_key_hash == (
            b'\xa8Jjc\x04}\xdd\xba\xe6\xd19\xb7\xa6Ee\xef\xf3\xa8\xec\xa1'
        )
        assert resp.issuer_name_hash == (
            b'~\xe6j\xe7r\x9a\xb3\xfc\xf8\xa2 dl\x16\xa1-`q\x08]'
        )
        assert isinstance(resp.hash_algorithm, hashes.SHA1)
        assert resp.serial_number == 271024907440004808294641238224534273948400
        assert len(resp.extensions) == 0

    def test_load_unauthorized(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-unauthorized.der"),
            ocsp.load_der_ocsp_response,
        )
        assert resp.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED
        with pytest.raises(ValueError):
            assert resp.signature_algorithm_oid
        with pytest.raises(ValueError):
            assert resp.signature
        with pytest.raises(ValueError):
            assert resp.tbs_response_bytes
        with pytest.raises(ValueError):
            assert resp.certificates
        with pytest.raises(ValueError):
            assert resp.responder_key_hash
        with pytest.raises(ValueError):
            assert resp.responder_name
        with pytest.raises(ValueError):
            assert resp.produced_at
        with pytest.raises(ValueError):
            assert resp.certificate_status
        with pytest.raises(ValueError):
            assert resp.revocation_time
        with pytest.raises(ValueError):
            assert resp.revocation_reason
        with pytest.raises(ValueError):
            assert resp.this_update
        with pytest.raises(ValueError):
            assert resp.next_update
        with pytest.raises(ValueError):
            assert resp.issuer_key_hash
        with pytest.raises(ValueError):
            assert resp.issuer_name_hash
        with pytest.raises(ValueError):
            assert resp.hash_algorithm
        with pytest.raises(ValueError):
            assert resp.serial_number
        with pytest.raises(ValueError):
            assert resp.extensions

    def test_load_revoked(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-revoked.der"),
            ocsp.load_der_ocsp_response,
        )
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
        assert resp.revocation_time == datetime.datetime(
            2016, 9, 2, 21, 28, 48
        )
        assert resp.revocation_reason is None

    def test_load_delegate_unknown_cert(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-delegate-unknown-cert.der"),
            ocsp.load_der_ocsp_response,
        )
        assert len(resp.certificates) == 1
        assert isinstance(resp.certificates[0], x509.Certificate)
        assert resp.certificate_status == ocsp.OCSPCertStatus.UNKNOWN

    def test_load_responder_key_hash(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-responder-key-hash.der"),
            ocsp.load_der_ocsp_response,
        )
        assert resp.responder_name is None
        assert resp.responder_key_hash == (
            b'\x0f\x80a\x1c\x821a\xd5/(\xe7\x8dF8\xb4,\xe1\xc6\xd9\xe2'
        )

    def test_load_revoked_reason(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-revoked-reason.der"),
            ocsp.load_der_ocsp_response,
        )
        assert resp.revocation_reason is x509.ReasonFlags.superseded

    def test_response_extensions(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-revoked-reason.der"),
            ocsp.load_der_ocsp_response,
        )
        assert len(resp.extensions) == 1
        ext = resp.extensions[0]
        assert ext.critical is False
        assert ext.value == x509.OCSPNonce(
            b'\x04\x105\x957\x9fa\x03\x83\x87\x89rW\x8f\xae\x99\xf7"'
        )

    def test_serialize_reponse(self):
        resp_bytes = load_vectors_from_file(
            filename=os.path.join("x509", "ocsp", "resp-revoked.der"),
            loader=lambda data: data.read(),
            mode="rb"
        )
        resp = ocsp.load_der_ocsp_response(resp_bytes)
        assert resp.public_bytes(serialization.Encoding.DER) == resp_bytes

    def test_invalid_serialize_encoding(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-revoked.der"),
            ocsp.load_der_ocsp_response,
        )
        with pytest.raises(ValueError):
            resp.public_bytes("invalid")
        with pytest.raises(ValueError):
            resp.public_bytes(serialization.Encoding.PEM)
