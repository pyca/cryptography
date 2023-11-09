# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import json
import os
from ipaddress import IPv4Address

from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.verification import PolicyBuilder, Store
from vectors import cryptography_vectors

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
}


def _get_limbo_peer(expected_peer, testcase_id):
    assert expected_peer is not None, f"{testcase_id}: no expected peer name"

    kind = expected_peer["kind"]
    assert kind in (
        "DNS",
        "IP",
    ), f"{testcase_id}: unexpected peer kind: {kind}"
    value = expected_peer["value"]
    if kind == "DNS":
        return x509.DNSName(value)
    else:
        return x509.IPAddress(IPv4Address(value))


def _limbo_testcase(testcase):
    features = testcase["features"]
    if features is not None and LIMBO_UNSUPPORTED_FEATURES.intersection(
        features
    ):
        return
    testcase_id = testcase["id"]
    assert (
        testcase["validation_kind"] == "SERVER"
    ), f"{testcase_id}: non-SERVER testcases not supported yet"
    assert (
        testcase["signature_algorithms"] is None
    ), f"{testcase_id}: signature_algorithms not supported yet"
    assert testcase["extended_key_usage"] is None or testcase[
        "extended_key_usage"
    ] == ["serverAuth"], f"{testcase_id}: extended_key_usage not supported yet"
    assert (
        testcase["expected_peer_names"] is None
    ), f"{testcase_id}: expected_peer_names not supported yet"

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
    peer_name = _get_limbo_peer(testcase["expected_peer_name"], testcase_id)
    validation_time = testcase["validation_time"]
    validation_time = (
        datetime.datetime.fromisoformat(validation_time)
        if validation_time is not None
        else None
    )
    max_chain_depth = testcase["max_chain_depth"]
    should_pass = testcase["expected_result"] == "SUCCESS"

    verifier = PolicyBuilder(
        time=validation_time,
        store=Store(trusted_certs),
        max_chain_depth=max_chain_depth,
    ).build_server_verifier(peer_name)

    try:
        verifier.verify(peer_certificate, untrusted_intermediates)
        assert (
            should_pass
        ), f"{testcase_id}: verification succeeded when we expected failure"
    except ValueError as e:
        assert (
            not should_pass
        ), f"{testcase_id}: verification failed when we expected success: {e}"


def test_limbo(subtests, pytestconfig):
    limbo_root = pytestconfig.getoption("--x509-limbo-root", skip=True)
    limbo_file = cryptography_vectors.open_vector_file(
        os.path.join(limbo_root, "limbo.json"), "r"
    )
    with limbo_file:
        limbo = json.load(limbo_file)
        testcases = limbo["testcases"]
        for testcase in testcases:
            with subtests.test():
                _limbo_testcase(testcase)
