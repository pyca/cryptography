# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import json
import os

import certifi

from cryptography import x509
from cryptography.x509 import ocsp

from ..utils import load_vectors_from_file


def test_object_identifier_constructor(benchmark):
    benchmark(x509.ObjectIdentifier, "1.3.6.1.4.1.11129.2.4.5")


def test_aki_public_bytes(benchmark):
    aki = x509.AuthorityKeyIdentifier(
        key_identifier=b"\x00" * 16,
        authority_cert_issuer=None,
        authority_cert_serial_number=None,
    )
    benchmark(aki.public_bytes)


def test_load_der_certificate(benchmark):
    cert_bytes = load_vectors_from_file(
        os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
        loader=lambda pemfile: pemfile.read(),
        mode="rb",
    )

    benchmark(x509.load_der_x509_certificate, cert_bytes)


def test_load_pem_certificate(benchmark):
    cert_bytes = load_vectors_from_file(
        os.path.join("x509", "cryptography.io.pem"),
        loader=lambda pemfile: pemfile.read(),
        mode="rb",
    )

    benchmark(x509.load_pem_x509_certificate, cert_bytes)


# ---------------------------------------------------------------------------
# Repeated property access — these measure the cost of the cached fast path.
# Each benchmark constructs the object once, then calls the getter repeatedly.
# ---------------------------------------------------------------------------


def test_certificate_subject(benchmark):
    cert_bytes = load_vectors_from_file(
        os.path.join("x509", "cryptography.io.pem"),
        loader=lambda f: f.read(),
        mode="rb",
    )
    cert = x509.load_pem_x509_certificate(cert_bytes)
    benchmark(lambda: cert.subject)


def test_certificate_issuer(benchmark):
    cert_bytes = load_vectors_from_file(
        os.path.join("x509", "cryptography.io.pem"),
        loader=lambda f: f.read(),
        mode="rb",
    )
    cert = x509.load_pem_x509_certificate(cert_bytes)
    benchmark(lambda: cert.issuer)


def test_certificate_public_key(benchmark):
    cert_bytes = load_vectors_from_file(
        os.path.join("x509", "cryptography.io.pem"),
        loader=lambda f: f.read(),
        mode="rb",
    )
    cert = x509.load_pem_x509_certificate(cert_bytes)
    benchmark(lambda: cert.public_key())


def test_certificate_signature_hash_algorithm(benchmark):
    cert_bytes = load_vectors_from_file(
        os.path.join("x509", "cryptography.io.pem"),
        loader=lambda f: f.read(),
        mode="rb",
    )
    cert = x509.load_pem_x509_certificate(cert_bytes)
    benchmark(lambda: cert.signature_hash_algorithm)


def test_certificate_signature_algorithm_oid(benchmark):
    cert_bytes = load_vectors_from_file(
        os.path.join("x509", "cryptography.io.pem"),
        loader=lambda f: f.read(),
        mode="rb",
    )
    cert = x509.load_pem_x509_certificate(cert_bytes)
    benchmark(lambda: cert.signature_algorithm_oid)


def test_crl_issuer(benchmark):
    crl_bytes = load_vectors_from_file(
        os.path.join("x509", "PKITS_data", "crls", "indirectCRLCA5CRL.crl"),
        loader=lambda f: f.read(),
        mode="rb",
    )
    crl = x509.load_der_x509_crl(crl_bytes)
    benchmark(lambda: crl.issuer)


def test_crl_serial_number_lookup_hit(benchmark):
    """Repeated lookup for a serial number present in the CRL."""
    crl_bytes = load_vectors_from_file(
        os.path.join("x509", "PKITS_data", "crls", "indirectCRLCA5CRL.crl"),
        loader=lambda f: f.read(),
        mode="rb",
    )
    crl = x509.load_der_x509_crl(crl_bytes)
    # Serial 1 is always present in this CRL.
    benchmark(lambda: crl.get_revoked_certificate_by_serial_number(1))


def test_crl_serial_number_lookup_miss(benchmark):
    """Repeated lookup for a serial number absent from the CRL."""
    crl_bytes = load_vectors_from_file(
        os.path.join("x509", "PKITS_data", "crls", "indirectCRLCA5CRL.crl"),
        loader=lambda f: f.read(),
        mode="rb",
    )
    crl = x509.load_der_x509_crl(crl_bytes)
    benchmark(lambda: crl.get_revoked_certificate_by_serial_number(99999))


def test_ocsp_request_properties(benchmark):
    req_bytes = load_vectors_from_file(
        os.path.join("x509", "ocsp", "req-sha1.der"),
        loader=lambda f: f.read(),
        mode="rb",
    )
    req = ocsp.load_der_ocsp_request(req_bytes)

    def bench():
        req.issuer_name_hash
        req.issuer_key_hash
        req.hash_algorithm
        req.serial_number

    benchmark(bench)


def test_ocsp_response_properties(benchmark):
    resp_bytes = load_vectors_from_file(
        os.path.join("x509", "ocsp", "resp-sha256.der"),
        loader=lambda f: f.read(),
        mode="rb",
    )
    resp = ocsp.load_der_ocsp_response(resp_bytes)

    def bench():
        resp.issuer_key_hash
        resp.serial_number
        resp.signature_hash_algorithm

    benchmark(bench)


def test_verify_docs_python_org(benchmark, pytestconfig):
    limbo_root = pytestconfig.getoption("--x509-limbo-root", skip=True)
    with open(os.path.join(limbo_root, "limbo.json"), "rb") as f:
        [testcase] = [
            tc
            for tc in json.load(f)["testcases"]
            if tc["id"] == "online::docs.python.org"
        ]

    with open(certifi.where(), "rb") as f:
        store = x509.verification.Store(
            x509.load_pem_x509_certificates(f.read())
        )

    leaf = x509.load_pem_x509_certificate(
        testcase["peer_certificate"].encode()
    )
    intermediates = [
        x509.load_pem_x509_certificate(c.encode())
        for c in testcase["untrusted_intermediates"]
    ]
    time = datetime.datetime.fromisoformat(testcase["validation_time"])

    def bench():
        verifier = (
            x509.verification.PolicyBuilder()
            .store(store)
            .time(time)
            .build_server_verifier(x509.DNSName("docs.python.org"))
        )
        verifier.verify(leaf, intermediates)

    benchmark(bench)
