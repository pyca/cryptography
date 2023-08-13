# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from ipaddress import IPv4Address
from cryptography.x509.general_name import DNSName, IPAddress
from cryptography.x509.verification import PolicyBuilder
import pytest


class TestPolicyBuilder:
    def test_none_subject(self):
        policy = PolicyBuilder(subject=None).build()
        assert policy.subject is None

    def test_ipaddress_subject(self):
        policy = PolicyBuilder(
            subject=IPAddress(IPv4Address("0.0.0.0"))
        ).build()
        assert policy.subject == IPAddress(IPv4Address("0.0.0.0"))

    def test_dnsname_subject(self):
        policy = PolicyBuilder(subject=DNSName("cryptography.io")).build()
        assert policy.subject == DNSName("cryptography.io")

    def test_subject_bad_types(self):
        # Subject must be none or a GeneralName type; nothing else is supported.
        with pytest.raises(TypeError):
            PolicyBuilder(subject="cryptography.io").build()
        with pytest.raises(TypeError):
            PolicyBuilder(subject="0.0.0.0").build()
        with pytest.raises(TypeError):
            PolicyBuilder(subject=IPv4Address("0.0.0.0")).build()
