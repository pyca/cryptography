# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import os
from ipaddress import IPv4Address

import pytest

from cryptography import x509
from cryptography.x509.general_name import DNSName, IPAddress
from cryptography.x509.verification import PolicyBuilder, Store
from tests.x509.test_x509 import _load_cert


class TestPolicyBuilder:
    def test_time_already_set(self):
        with pytest.raises(ValueError):
            PolicyBuilder().time(datetime.datetime.now()).time(
                datetime.datetime.now()
            )

    def test_ipaddress_subject(self):
        policy = PolicyBuilder().build_server_verifier(
            IPAddress(IPv4Address("0.0.0.0"))
        )
        assert policy.subject == IPAddress(IPv4Address("0.0.0.0"))

    def test_dnsname_subject(self):
        policy = PolicyBuilder().build_server_verifier(
            DNSName("cryptography.io")
        )
        assert policy.subject == DNSName("cryptography.io")

    def test_subject_bad_types(self):
        # Subject must be none or a GeneralName type; nothing else is
        # supported.
        with pytest.raises(TypeError):
            PolicyBuilder().build_server_verifier(
                "cryptography.io"  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().build_server_verifier(
                "0.0.0.0"  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().build_server_verifier(
                IPv4Address("0.0.0.0")  # type: ignore[arg-type]
            )

    def test_builder_pattern(self):
        now = datetime.datetime.now().replace(microsecond=0)

        builder = PolicyBuilder()
        builder = builder.time(now)

        verifier = builder.build_server_verifier(DNSName("cryptography.io"))
        assert verifier.subject == DNSName("cryptography.io")
        assert verifier.validation_time == now


class TestStore:
    def test_store_rejects_empty_list(self):
        with pytest.raises(ValueError):
            Store([])

    def test_store_rejects_non_certificates(self):
        with pytest.raises(TypeError):
            Store(["not a cert"])  # type: ignore[list-item]

    def test_store_initializes(self):
        cert = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
        )
        assert Store([cert]) is not None
