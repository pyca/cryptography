# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import base64
import datetime
import os

import pytest

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509 import ocsp

from .test_x509 import _load_cert
from ..hazmat.primitives.fixtures_ec import EC_KEY_SECP256R1
from ..utils import load_vectors_from_file


def _load_data(filename, loader):
    return load_vectors_from_file(
        filename=filename, loader=lambda data: loader(data.read()), mode="rb"
    )


def _cert_and_issuer():
    from cryptography.hazmat.backends.openssl.backend import backend

    cert = _load_cert(
        os.path.join("x509", "cryptography.io.pem"),
        x509.load_pem_x509_certificate,
        backend,
    )
    issuer = _load_cert(
        os.path.join("x509", "rapidssl_sha256_ca_g3.pem"),
        x509.load_pem_x509_certificate,
        backend,
    )
    return cert, issuer


def _generate_root(private_key=None, algorithm=hashes.SHA256()):
    from cryptography.hazmat.backends.openssl.backend import backend

    if private_key is None:
        private_key = EC_KEY_SECP256R1.private_key(backend)

    subject = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Cryptography CA"),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .serial_number(123456789)
        .issuer_name(subject)
        .subject_name(subject)
        .public_key(private_key.public_key())
        .not_valid_before(datetime.datetime.now())
        .not_valid_after(
            datetime.datetime.now() + datetime.timedelta(days=3650)
        )
    )

    cert = builder.sign(private_key, algorithm, backend)
    return cert, private_key


class TestOCSPRequest(object):
    def test_bad_request(self):
        with pytest.raises(ValueError):
            ocsp.load_der_ocsp_request(b"invalid")

    def test_load_request(self):
        req = _load_data(
            os.path.join("x509", "ocsp", "req-sha1.der"),
            ocsp.load_der_ocsp_request,
        )
        assert req.issuer_name_hash == (
            b"8\xcaF\x8c\x07D\x8d\xf4\x81\x96" b"\xc7mmLpQ\x9e`\xa7\xbd"
        )
        assert req.issuer_key_hash == (
            b"yu\xbb\x84:\xcb,\xdez\t\xbe1" b"\x1bC\xbc\x1c*MSX"
        )
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
            mode="rb",
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
            builder.add_extension(
                "notanext",  # type:ignore[arg-type]
                False,
            )

    def test_create_ocsp_request_invalid_cert(self):
        cert, issuer = _cert_and_issuer()
        builder = ocsp.OCSPRequestBuilder()
        with pytest.raises(TypeError):
            builder.add_certificate(
                b"notacert",  # type:ignore[arg-type]
                issuer,
                hashes.SHA1(),
            )

        with pytest.raises(TypeError):
            builder.add_certificate(
                cert,
                b"notacert",  # type:ignore[arg-type]
                hashes.SHA1(),
            )

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
        ],
    )
    def test_create_ocsp_request_with_extension(self, ext, critical):
        cert, issuer = _cert_and_issuer()
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(
            cert, issuer, hashes.SHA1()
        ).add_extension(ext, critical)
        req = builder.build()
        assert len(req.extensions) == 1
        assert req.extensions[0].value == ext
        assert req.extensions[0].oid == ext.oid
        assert req.extensions[0].critical is critical


class TestOCSPResponseBuilder(object):
    def test_add_response_twice(self):
        cert, issuer = _cert_and_issuer()
        time = datetime.datetime.now()
        builder = ocsp.OCSPResponseBuilder()
        builder = builder.add_response(
            cert,
            issuer,
            hashes.SHA256(),
            ocsp.OCSPCertStatus.GOOD,
            time,
            time,
            None,
            None,
        )
        with pytest.raises(ValueError):
            builder.add_response(
                cert,
                issuer,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.GOOD,
                time,
                time,
                None,
                None,
            )

    def test_invalid_add_response(self):
        cert, issuer = _cert_and_issuer()
        time = datetime.datetime.utcnow()
        reason = x509.ReasonFlags.cessation_of_operation
        builder = ocsp.OCSPResponseBuilder()
        with pytest.raises(TypeError):
            builder.add_response(
                "bad",  # type:ignore[arg-type]
                issuer,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.GOOD,
                time,
                time,
                None,
                None,
            )
        with pytest.raises(TypeError):
            builder.add_response(
                cert,
                "bad",  # type:ignore[arg-type]
                hashes.SHA256(),
                ocsp.OCSPCertStatus.GOOD,
                time,
                time,
                None,
                None,
            )
        with pytest.raises(ValueError):
            builder.add_response(
                cert,
                issuer,
                "notahash",  # type:ignore[arg-type]
                ocsp.OCSPCertStatus.GOOD,
                time,
                time,
                None,
                None,
            )
        with pytest.raises(TypeError):
            builder.add_response(
                cert,
                issuer,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.GOOD,
                "bad",  # type:ignore[arg-type]
                time,
                None,
                None,
            )
        with pytest.raises(TypeError):
            builder.add_response(
                cert,
                issuer,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.GOOD,
                time,
                "bad",  # type:ignore[arg-type]
                None,
                None,
            )

        with pytest.raises(TypeError):
            builder.add_response(
                cert,
                issuer,
                hashes.SHA256(),
                0,  # type:ignore[arg-type]
                time,
                time,
                None,
                None,
            )
        with pytest.raises(ValueError):
            builder.add_response(
                cert,
                issuer,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.GOOD,
                time,
                time,
                time,
                None,
            )
        with pytest.raises(ValueError):
            builder.add_response(
                cert,
                issuer,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.GOOD,
                time,
                time,
                None,
                reason,
            )
        with pytest.raises(TypeError):
            builder.add_response(
                cert,
                issuer,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.REVOKED,
                time,
                time,
                None,
                reason,
            )
        with pytest.raises(TypeError):
            builder.add_response(
                cert,
                issuer,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.REVOKED,
                time,
                time,
                time,
                0,  # type:ignore[arg-type]
            )
        with pytest.raises(ValueError):
            builder.add_response(
                cert,
                issuer,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.REVOKED,
                time,
                time,
                time - datetime.timedelta(days=36500),
                None,
            )

    def test_invalid_certificates(self):
        builder = ocsp.OCSPResponseBuilder()
        with pytest.raises(ValueError):
            builder.certificates([])
        with pytest.raises(TypeError):
            builder.certificates(["notacert"])  # type: ignore[list-item]
        with pytest.raises(TypeError):
            builder.certificates("invalid")  # type: ignore[arg-type]

        _, issuer = _cert_and_issuer()
        builder = builder.certificates([issuer])
        with pytest.raises(ValueError):
            builder.certificates([issuer])

    def test_invalid_responder_id(self):
        builder = ocsp.OCSPResponseBuilder()
        cert, _ = _cert_and_issuer()
        with pytest.raises(TypeError):
            builder.responder_id(
                ocsp.OCSPResponderEncoding.HASH,
                "invalid",  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            builder.responder_id("notanenum", cert)  # type: ignore[arg-type]

        builder = builder.responder_id(ocsp.OCSPResponderEncoding.NAME, cert)
        with pytest.raises(ValueError):
            builder.responder_id(ocsp.OCSPResponderEncoding.NAME, cert)

    def test_invalid_extension(self):
        builder = ocsp.OCSPResponseBuilder()
        with pytest.raises(TypeError):
            builder.add_extension(
                "notanextension", True  # type: ignore[arg-type]
            )

    def test_sign_no_response(self):
        builder = ocsp.OCSPResponseBuilder()
        root_cert, private_key = _generate_root()
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.NAME, root_cert
        )
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256())

    def test_sign_no_responder_id(self):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        _, private_key = _generate_root()
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        builder = builder.add_response(
            cert,
            issuer,
            hashes.SHA1(),
            ocsp.OCSPCertStatus.GOOD,
            this_update,
            next_update,
            None,
            None,
        )
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256())

    def test_sign_invalid_hash_algorithm(self):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        root_cert, private_key = _generate_root()
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.NAME, root_cert
        ).add_response(
            cert,
            issuer,
            hashes.SHA1(),
            ocsp.OCSPCertStatus.GOOD,
            this_update,
            next_update,
            None,
            None,
        )
        with pytest.raises(TypeError):
            builder.sign(private_key, "notahash")  # type: ignore[arg-type]

    def test_sign_good_cert(self):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        root_cert, private_key = _generate_root()
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.NAME, root_cert
        ).add_response(
            cert,
            issuer,
            hashes.SHA1(),
            ocsp.OCSPCertStatus.GOOD,
            this_update,
            next_update,
            None,
            None,
        )
        resp = builder.sign(private_key, hashes.SHA256())
        assert resp.responder_name == root_cert.subject
        assert resp.responder_key_hash is None
        assert (current_time - resp.produced_at).total_seconds() < 10
        assert (
            resp.signature_algorithm_oid
            == x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256
        )
        assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD
        assert resp.revocation_time is None
        assert resp.revocation_reason is None
        assert resp.this_update == this_update
        assert resp.next_update == next_update
        private_key.public_key().verify(
            resp.signature, resp.tbs_response_bytes, ec.ECDSA(hashes.SHA256())
        )

    def test_sign_revoked_cert(self):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        root_cert, private_key = _generate_root()
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        revoked_date = this_update - datetime.timedelta(days=300)
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.NAME, root_cert
        ).add_response(
            cert,
            issuer,
            hashes.SHA1(),
            ocsp.OCSPCertStatus.REVOKED,
            this_update,
            next_update,
            revoked_date,
            None,
        )
        resp = builder.sign(private_key, hashes.SHA256())
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
        assert resp.revocation_time == revoked_date
        assert resp.revocation_reason is None
        assert resp.this_update == this_update
        assert resp.next_update == next_update
        private_key.public_key().verify(
            resp.signature, resp.tbs_response_bytes, ec.ECDSA(hashes.SHA256())
        )

    def test_sign_with_appended_certs(self):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        root_cert, private_key = _generate_root()
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        builder = (
            builder.responder_id(ocsp.OCSPResponderEncoding.NAME, root_cert)
            .add_response(
                cert,
                issuer,
                hashes.SHA1(),
                ocsp.OCSPCertStatus.GOOD,
                this_update,
                next_update,
                None,
                None,
            )
            .certificates([root_cert])
        )
        resp = builder.sign(private_key, hashes.SHA256())
        assert resp.certificates == [root_cert]

    def test_sign_revoked_no_next_update(self):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        root_cert, private_key = _generate_root()
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        revoked_date = this_update - datetime.timedelta(days=300)
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.NAME, root_cert
        ).add_response(
            cert,
            issuer,
            hashes.SHA1(),
            ocsp.OCSPCertStatus.REVOKED,
            this_update,
            None,
            revoked_date,
            None,
        )
        resp = builder.sign(private_key, hashes.SHA256())
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
        assert resp.revocation_time == revoked_date
        assert resp.revocation_reason is None
        assert resp.this_update == this_update
        assert resp.next_update is None
        private_key.public_key().verify(
            resp.signature, resp.tbs_response_bytes, ec.ECDSA(hashes.SHA256())
        )

    def test_sign_revoked_with_reason(self):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        root_cert, private_key = _generate_root()
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        revoked_date = this_update - datetime.timedelta(days=300)
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.NAME, root_cert
        ).add_response(
            cert,
            issuer,
            hashes.SHA1(),
            ocsp.OCSPCertStatus.REVOKED,
            this_update,
            next_update,
            revoked_date,
            x509.ReasonFlags.key_compromise,
        )
        resp = builder.sign(private_key, hashes.SHA256())
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
        assert resp.revocation_time == revoked_date
        assert resp.revocation_reason is x509.ReasonFlags.key_compromise
        assert resp.this_update == this_update
        assert resp.next_update == next_update
        private_key.public_key().verify(
            resp.signature, resp.tbs_response_bytes, ec.ECDSA(hashes.SHA256())
        )

    def test_sign_responder_id_key_hash(self):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        root_cert, private_key = _generate_root()
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.HASH, root_cert
        ).add_response(
            cert,
            issuer,
            hashes.SHA1(),
            ocsp.OCSPCertStatus.GOOD,
            this_update,
            next_update,
            None,
            None,
        )
        resp = builder.sign(private_key, hashes.SHA256())
        assert resp.responder_name is None
        assert resp.responder_key_hash == (
            b"\x8ca\x94\xe0\x948\xed\x89\xd8\xd4N\x89p\t\xd6\xf9^_\xec}"
        )
        private_key.public_key().verify(
            resp.signature, resp.tbs_response_bytes, ec.ECDSA(hashes.SHA256())
        )

    def test_invalid_sign_responder_cert_does_not_match_private_key(self):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        root_cert, private_key = _generate_root()
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.HASH, root_cert
        ).add_response(
            cert,
            issuer,
            hashes.SHA1(),
            ocsp.OCSPCertStatus.GOOD,
            this_update,
            next_update,
            None,
            None,
        )
        from cryptography.hazmat.backends.openssl.backend import backend

        diff_key = ec.generate_private_key(ec.SECP256R1(), backend)
        with pytest.raises(ValueError):
            builder.sign(diff_key, hashes.SHA256())

    def test_sign_with_extension(self):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        root_cert, private_key = _generate_root()
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        builder = (
            builder.responder_id(ocsp.OCSPResponderEncoding.HASH, root_cert)
            .add_response(
                cert,
                issuer,
                hashes.SHA1(),
                ocsp.OCSPCertStatus.GOOD,
                this_update,
                next_update,
                None,
                None,
            )
            .add_extension(x509.OCSPNonce(b"012345"), False)
        )
        resp = builder.sign(private_key, hashes.SHA256())
        assert len(resp.extensions) == 1
        assert resp.extensions[0].value == x509.OCSPNonce(b"012345")
        assert resp.extensions[0].critical is False
        private_key.public_key().verify(
            resp.signature, resp.tbs_response_bytes, ec.ECDSA(hashes.SHA256())
        )

    @pytest.mark.parametrize(
        ("status", "der"),
        [
            (ocsp.OCSPResponseStatus.MALFORMED_REQUEST, b"0\x03\n\x01\x01"),
            (ocsp.OCSPResponseStatus.INTERNAL_ERROR, b"0\x03\n\x01\x02"),
            (ocsp.OCSPResponseStatus.TRY_LATER, b"0\x03\n\x01\x03"),
            (ocsp.OCSPResponseStatus.SIG_REQUIRED, b"0\x03\n\x01\x05"),
            (ocsp.OCSPResponseStatus.UNAUTHORIZED, b"0\x03\n\x01\x06"),
        ],
    )
    def test_build_non_successful_statuses(self, status, der):
        resp = ocsp.OCSPResponseBuilder.build_unsuccessful(status)
        assert resp.response_status is status
        assert resp.public_bytes(serialization.Encoding.DER) == der

    def test_invalid_build_not_a_status(self):
        with pytest.raises(TypeError):
            ocsp.OCSPResponseBuilder.build_unsuccessful(
                "notastatus"  # type: ignore[arg-type]
            )

    def test_invalid_build_successful_status(self):
        with pytest.raises(ValueError):
            ocsp.OCSPResponseBuilder.build_unsuccessful(
                ocsp.OCSPResponseStatus.SUCCESSFUL
            )


class TestSignedCertificateTimestampsExtension(object):
    def test_init(self):
        with pytest.raises(TypeError):
            x509.SignedCertificateTimestamps(
                [object()]  # type: ignore[list-item]
            )

    def test_repr(self):
        assert repr(x509.SignedCertificateTimestamps([])) == (
            "<SignedCertificateTimestamps([])>"
        )

    @pytest.mark.supported(
        only_if=lambda backend: (backend._lib.Cryptography_HAS_SCT),
        skip_message="Requires CT support",
    )
    def test_eq(self, backend):
        sct1 = (
            _load_data(
                os.path.join("x509", "ocsp", "resp-sct-extension.der"),
                ocsp.load_der_ocsp_response,
            )
            .single_extensions.get_extension_for_class(
                x509.SignedCertificateTimestamps
            )
            .value
        )
        sct2 = (
            _load_data(
                os.path.join("x509", "ocsp", "resp-sct-extension.der"),
                ocsp.load_der_ocsp_response,
            )
            .single_extensions.get_extension_for_class(
                x509.SignedCertificateTimestamps
            )
            .value
        )
        assert sct1 == sct2

    @pytest.mark.supported(
        only_if=lambda backend: (backend._lib.Cryptography_HAS_SCT),
        skip_message="Requires CT support",
    )
    def test_ne(self, backend):
        sct1 = (
            _load_data(
                os.path.join("x509", "ocsp", "resp-sct-extension.der"),
                ocsp.load_der_ocsp_response,
            )
            .single_extensions.get_extension_for_class(
                x509.SignedCertificateTimestamps
            )
            .value
        )
        sct2 = x509.SignedCertificateTimestamps([])
        assert sct1 != sct2
        assert sct1 != object()

    @pytest.mark.supported(
        only_if=lambda backend: (backend._lib.Cryptography_HAS_SCT),
        skip_message="Requires CT support",
    )
    def test_hash(self, backend):
        sct1 = (
            _load_data(
                os.path.join("x509", "ocsp", "resp-sct-extension.der"),
                ocsp.load_der_ocsp_response,
            )
            .single_extensions.get_extension_for_class(
                x509.SignedCertificateTimestamps
            )
            .value
        )
        sct2 = (
            _load_data(
                os.path.join("x509", "ocsp", "resp-sct-extension.der"),
                ocsp.load_der_ocsp_response,
            )
            .single_extensions.get_extension_for_class(
                x509.SignedCertificateTimestamps
            )
            .value
        )
        sct3 = x509.SignedCertificateTimestamps([])
        assert hash(sct1) == hash(sct2)
        assert hash(sct1) != hash(sct3)


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
            backend,
        )
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert (
            resp.signature_algorithm_oid
            == x509.SignatureAlgorithmOID.RSA_WITH_SHA256
        )
        assert isinstance(resp.signature_hash_algorithm, hashes.SHA256)
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
            resp.signature_hash_algorithm,
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
            b"\xa8Jjc\x04}\xdd\xba\xe6\xd19\xb7\xa6Ee\xef\xf3\xa8\xec\xa1"
        )
        assert resp.issuer_name_hash == (
            b"~\xe6j\xe7r\x9a\xb3\xfc\xf8\xa2 dl\x16\xa1-`q\x08]"
        )
        assert isinstance(resp.hash_algorithm, hashes.SHA1)
        assert resp.serial_number == 271024907440004808294641238224534273948400
        assert len(resp.extensions) == 0

    def test_load_multi_valued_response(self):
        with pytest.raises(ValueError):
            _load_data(
                os.path.join("x509", "ocsp", "ocsp-army.deps.mil-resp.der"),
                ocsp.load_der_ocsp_response,
            )

    def test_load_unauthorized(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-unauthorized.der"),
            ocsp.load_der_ocsp_response,
        )
        assert resp.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED
        with pytest.raises(ValueError):
            resp.signature_algorithm_oid
        with pytest.raises(ValueError):
            resp.signature_hash_algorithm
        with pytest.raises(ValueError):
            resp.signature
        with pytest.raises(ValueError):
            resp.tbs_response_bytes
        with pytest.raises(ValueError):
            resp.certificates
        with pytest.raises(ValueError):
            resp.responder_key_hash
        with pytest.raises(ValueError):
            resp.responder_name
        with pytest.raises(ValueError):
            resp.produced_at
        with pytest.raises(ValueError):
            resp.certificate_status
        with pytest.raises(ValueError):
            resp.revocation_time
        with pytest.raises(ValueError):
            resp.revocation_reason
        with pytest.raises(ValueError):
            resp.this_update
        with pytest.raises(ValueError):
            resp.next_update
        with pytest.raises(ValueError):
            resp.issuer_key_hash
        with pytest.raises(ValueError):
            resp.issuer_name_hash
        with pytest.raises(ValueError):
            resp.hash_algorithm
        with pytest.raises(ValueError):
            resp.serial_number
        with pytest.raises(ValueError):
            resp.extensions

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

    def test_load_invalid_signature_oid(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-invalid-signature-oid.der"),
            ocsp.load_der_ocsp_response,
        )
        assert resp.signature_algorithm_oid == x509.ObjectIdentifier(
            "1.2.840.113549.1.1.2"
        )
        with pytest.raises(UnsupportedAlgorithm):
            resp.signature_hash_algorithm

    def test_load_responder_key_hash(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-responder-key-hash.der"),
            ocsp.load_der_ocsp_response,
        )
        assert resp.responder_name is None
        assert resp.responder_key_hash == (
            b"\x0f\x80a\x1c\x821a\xd5/(\xe7\x8dF8\xb4,\xe1\xc6\xd9\xe2"
        )

    def test_load_revoked_reason(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-revoked-reason.der"),
            ocsp.load_der_ocsp_response,
        )
        assert resp.revocation_reason is x509.ReasonFlags.superseded

    def test_load_revoked_no_next_update(self):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-revoked-no-next-update.der"),
            ocsp.load_der_ocsp_response,
        )
        assert resp.serial_number == 16160
        assert resp.next_update is None

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
            mode="rb",
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

    @pytest.mark.supported(
        only_if=lambda backend: (backend._lib.Cryptography_HAS_SCT),
        skip_message="Requires CT support",
    )
    def test_single_extensions_sct(self, backend):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-sct-extension.der"),
            ocsp.load_der_ocsp_response,
        )
        assert len(resp.single_extensions) == 1
        ext = resp.single_extensions[0]
        assert ext.oid == x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.5")
        assert len(ext.value) == 4
        log_ids = [base64.b64encode(sct.log_id) for sct in ext.value]
        assert log_ids == [
            b"RJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gag=",
            b"b1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RM=",
            b"u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=",
            b"7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=",
        ]

    @pytest.mark.supported(
        only_if=lambda backend: (
            not backend._lib.CRYPTOGRAPHY_OPENSSL_110F_OR_GREATER
        ),
        skip_message="Requires OpenSSL < 1.1.0f",
    )
    def test_skips_single_extensions_scts_if_unsupported(self, backend):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-sct-extension.der"),
            ocsp.load_der_ocsp_response,
        )
        with pytest.raises(x509.ExtensionNotFound):
            resp.single_extensions.get_extension_for_class(
                x509.SignedCertificateTimestamps
            )

        ext = resp.single_extensions.get_extension_for_oid(
            x509.ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS
        )
        assert isinstance(ext.value, x509.UnrecognizedExtension)

    def test_single_extensions(self, backend):
        resp = _load_data(
            os.path.join("x509", "ocsp", "resp-single-extension-reason.der"),
            ocsp.load_der_ocsp_response,
        )
        assert len(resp.single_extensions) == 1
        ext = resp.single_extensions[0]
        assert ext.oid == x509.CRLReason.oid
        assert ext.value == x509.CRLReason(x509.ReasonFlags.unspecified)


class TestOCSPEdDSA(object):
    @pytest.mark.supported(
        only_if=lambda backend: backend.ed25519_supported(),
        skip_message="Requires OpenSSL with Ed25519 support / OCSP",
    )
    def test_invalid_algorithm(self, backend):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        private_key = ed25519.Ed25519PrivateKey.generate()
        root_cert, _ = _generate_root(private_key, None)
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        revoked_date = this_update - datetime.timedelta(days=300)
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.NAME, root_cert
        ).add_response(
            cert,
            issuer,
            hashes.SHA1(),
            ocsp.OCSPCertStatus.REVOKED,
            this_update,
            next_update,
            revoked_date,
            x509.ReasonFlags.key_compromise,
        )
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256())

    @pytest.mark.supported(
        only_if=lambda backend: backend.ed25519_supported(),
        skip_message="Requires OpenSSL with Ed25519 support / OCSP",
    )
    def test_sign_ed25519(self, backend):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        private_key = ed25519.Ed25519PrivateKey.generate()
        root_cert, _ = _generate_root(private_key, None)
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        revoked_date = this_update - datetime.timedelta(days=300)
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.NAME, root_cert
        ).add_response(
            cert,
            issuer,
            hashes.SHA1(),
            ocsp.OCSPCertStatus.REVOKED,
            this_update,
            next_update,
            revoked_date,
            x509.ReasonFlags.key_compromise,
        )
        resp = builder.sign(private_key, None)
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
        assert resp.revocation_time == revoked_date
        assert resp.revocation_reason is x509.ReasonFlags.key_compromise
        assert resp.this_update == this_update
        assert resp.next_update == next_update
        assert resp.signature_hash_algorithm is None
        assert (
            resp.signature_algorithm_oid == x509.SignatureAlgorithmOID.ED25519
        )
        private_key.public_key().verify(
            resp.signature, resp.tbs_response_bytes
        )

    @pytest.mark.supported(
        only_if=lambda backend: backend.ed448_supported(),
        skip_message="Requires OpenSSL with Ed448 support / OCSP",
    )
    def test_sign_ed448(self, backend):
        builder = ocsp.OCSPResponseBuilder()
        cert, issuer = _cert_and_issuer()
        private_key = ed448.Ed448PrivateKey.generate()
        root_cert, _ = _generate_root(private_key, None)
        current_time = datetime.datetime.utcnow().replace(microsecond=0)
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        revoked_date = this_update - datetime.timedelta(days=300)
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.NAME, root_cert
        ).add_response(
            cert,
            issuer,
            hashes.SHA1(),
            ocsp.OCSPCertStatus.REVOKED,
            this_update,
            next_update,
            revoked_date,
            x509.ReasonFlags.key_compromise,
        )
        resp = builder.sign(private_key, None)
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
        assert resp.revocation_time == revoked_date
        assert resp.revocation_reason is x509.ReasonFlags.key_compromise
        assert resp.this_update == this_update
        assert resp.next_update == next_update
        assert resp.signature_hash_algorithm is None
        assert resp.signature_algorithm_oid == x509.SignatureAlgorithmOID.ED448
        private_key.public_key().verify(
            resp.signature, resp.tbs_response_bytes
        )
