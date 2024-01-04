# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import ipaddress
import json
import os

import pytest

from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.verification import (
    PolicyBuilder,
    Store,
    VerificationError,
)

LIMBO_UNSUPPORTED_FEATURES = {
    # NOTE: Path validation is required to reject wildcards on public suffixes,
    # however this isn't practical and most implementations make no attempt to
    # comply with this.
    "pedantic-public-suffix-wildcard",
    # TODO: We don't support Distinguished Name Constraints yet.
    "name-constraint-dn",
    # Our support for custom EKUs is limited, and we (like most impls.) don't
    # handle all EKU conditions under CABF.
    "pedantic-webpki-eku",
    # Similarly: contains tests that fail based on a strict reading of RFC 5280
    # but are widely ignored by validators.
    "pedantic-rfc5280",
    # In rare circumstances, CABF relaxes RFC 5280's prescriptions in
    # incompatible ways. Our validator always tries (by default) to comply
    # closer to CABF, so we skip these.
    "rfc5280-incompatible-with-webpki",
    # We do not support policy constraints.
    "has-policy-constraints",
}

LIMBO_SKIP_TESTCASES = {
    # We unconditionally count intermediate certificates for pathlen and max
    # depth constraint purposes, even when self-issued.
    # This is a violation of RFC 5280, but is consistent with Go's crypto/x509
    # and Rust's webpki crate do.
    "pathlen::self-issued-certs-pathlen",
    "pathlen::max-chain-depth-1-self-issued",
    # We allow certificates with serial numbers of zero. This is
    # invalid under RFC 5280 but is widely violated by certs in common
    # trust stores.
    "rfc5280::serial::zero",
    # We allow CAs that don't have AKIs, which is forbidden under
    # RFC 5280. This is consistent with what Go's crypto/x509 and Rust's
    # webpki crate do.
    "rfc5280::ski::root-missing-ski",
    "rfc5280::ski::intermediate-missing-ski",
    # We currently allow intermediate CAs that don't have AKIs, which
    # is technically forbidden under CABF. This is consistent with what
    # Go's crypto/x509 and Rust's webpki crate do.
    "rfc5280::aki::intermediate-missing-aki",
    # We allow root CAs where the AKI and SKI mismatch, which is technically
    # forbidden under CABF. This is consistent with what
    # Go's crypto/x509 and Rust's webpki crate do.
    "webpki::aki::root-with-aki-ski-mismatch",
    # We disallow CAs in the leaf position, which is explicitly forbidden
    # by CABF (but implicitly permitted under RFC 5280). This is consistent
    # with what webpki and rustls do, but inconsistent with Go and OpenSSL.
    "rfc5280::ca-as-leaf",
    "pathlen::validation-ignores-pathlen-in-leaf",
}


def _get_limbo_peer(expected_peer):
    kind = expected_peer["kind"]
    assert kind in ("DNS", "IP")
    value = expected_peer["value"]
    if kind == "DNS":
        return x509.DNSName(value)
    else:
        return x509.IPAddress(ipaddress.ip_address(value))


def _limbo_testcase(id_, testcase):
    if id_ in LIMBO_SKIP_TESTCASES:
        return

    features = testcase["features"]
    if LIMBO_UNSUPPORTED_FEATURES.intersection(features):
        return
    assert testcase["validation_kind"] == "SERVER"
    assert testcase["signature_algorithms"] == []
    assert testcase["extended_key_usage"] == [] or testcase[
        "extended_key_usage"
    ] == ["serverAuth"]
    assert testcase["expected_peer_names"] == []

    trusted_certs = [
        load_pem_x509_certificate(cert.encode())
        for cert in testcase["trusted_certs"]
    ]
    untrusted_intermediates = [
        load_pem_x509_certificate(cert.encode())
        for cert in testcase["untrusted_intermediates"]
    ]
    peer_certificate = load_pem_x509_certificate(
        testcase["peer_certificate"].encode()
    )
    peer_name = _get_limbo_peer(testcase["expected_peer_name"])
    validation_time = testcase["validation_time"]
    validation_time = (
        datetime.datetime.fromisoformat(validation_time)
        if validation_time is not None
        else None
    )
    max_chain_depth = testcase["max_chain_depth"]
    should_pass = testcase["expected_result"] == "SUCCESS"

    builder = PolicyBuilder().store(Store(trusted_certs))
    if validation_time is not None:
        builder = builder.time(validation_time)
    if max_chain_depth is not None:
        builder = builder.max_chain_depth(max_chain_depth)

    verifier = builder.build_server_verifier(peer_name)

    if should_pass:
        built_chain = verifier.verify(
            peer_certificate, untrusted_intermediates
        )

        # Assert that the verifier returns chains in [EE, ..., TA] order.
        assert built_chain[0] == peer_certificate
        for intermediate in built_chain[1:-1]:
            assert intermediate in untrusted_intermediates
        assert built_chain[-1] in trusted_certs
    else:
        with pytest.raises(VerificationError):
            verifier.verify(peer_certificate, untrusted_intermediates)


def test_limbo(subtests, pytestconfig):
    limbo_root = pytestconfig.getoption("--x509-limbo-root", skip=True)
    limbo_path = os.path.join(limbo_root, "limbo.json")
    with open(limbo_path, mode="rb") as limbo_file:
        limbo = json.load(limbo_file)
        testcases = limbo["testcases"]
        for testcase in testcases:
            with subtests.test():
                # NOTE: Pass in the id separately to make pytest
                # error renderings slightly nicer.
                _limbo_testcase(testcase["id"], testcase)
