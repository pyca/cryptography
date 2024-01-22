# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import os
from functools import lru_cache
from ipaddress import IPv4Address

import pytest

from cryptography import x509
from cryptography.x509.general_name import DNSName, IPAddress
from cryptography.x509.verification import PolicyBuilder, Store
from tests.x509.test_x509 import _load_cert


@lru_cache(maxsize=1)
def dummy_store() -> Store:
    cert = _load_cert(
        os.path.join("x509", "cryptography.io.pem"),
        x509.load_pem_x509_certificate,
    )
    return Store([cert])


class TestPolicyBuilder:
    def test_time_already_set(self):
        with pytest.raises(ValueError):
            PolicyBuilder().time(datetime.datetime.now()).time(
                datetime.datetime.now()
            )

    def test_store_already_set(self):
        with pytest.raises(ValueError):
            PolicyBuilder().store(dummy_store()).store(dummy_store())

    def test_max_chain_depth_already_set(self):
        with pytest.raises(ValueError):
            PolicyBuilder().max_chain_depth(8).max_chain_depth(9)

    def test_ipaddress_subject(self):
        policy = (
            PolicyBuilder()
            .store(dummy_store())
            .build_server_verifier(IPAddress(IPv4Address("0.0.0.0")))
        )
        assert policy.subject == IPAddress(IPv4Address("0.0.0.0"))

    def test_dnsname_subject(self):
        policy = (
            PolicyBuilder()
            .store(dummy_store())
            .build_server_verifier(DNSName("cryptography.io"))
        )
        assert policy.subject == DNSName("cryptography.io")

    def test_subject_bad_types(self):
        # Subject must be a supported GeneralName type
        with pytest.raises(TypeError):
            PolicyBuilder().store(dummy_store()).build_server_verifier(
                "cryptography.io"  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().store(dummy_store()).build_server_verifier(
                "0.0.0.0"  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().store(dummy_store()).build_server_verifier(
                IPv4Address("0.0.0.0")  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().store(dummy_store()).build_server_verifier(None)  # type: ignore[arg-type]

    def test_builder_pattern(self):
        now = datetime.datetime.now().replace(microsecond=0)
        store = dummy_store()
        max_chain_depth = 16

        builder = PolicyBuilder()
        builder = builder.time(now)
        builder = builder.store(store)
        builder = builder.max_chain_depth(max_chain_depth)

        verifier = builder.build_server_verifier(DNSName("cryptography.io"))
        assert verifier.subject == DNSName("cryptography.io")
        assert verifier.validation_time == now
        assert verifier.store == store
        assert verifier.max_chain_depth == max_chain_depth

    def test_build_server_verifier_missing_store(self):
        with pytest.raises(
            ValueError, match="A server verifier must have a trust store"
        ):
            PolicyBuilder().build_server_verifier(DNSName("cryptography.io"))


class TestStore:
    def test_store_rejects_empty_list(self):
        with pytest.raises(ValueError):
            Store([])

    def test_store_rejects_non_certificates(self):
        with pytest.raises(TypeError):
            Store(["not a cert"])  # type: ignore[list-item]


class TestServerVerifier:
    @pytest.mark.parametrize(
        ("validation_time", "valid"),
        [
            # 03:15:02 UTC+2, or 1 second before expiry in UTC
            ("2018-11-16T03:15:02+02:00", True),
            # 00:15:04 UTC-1, or 1 second after expiry in UTC
            ("2018-11-16T00:15:04-01:00", False),
        ],
    )
    def test_verify_tz_aware(self, validation_time, valid):
        # expires 2018-11-16 01:15:03 UTC
        leaf = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])

        builder = PolicyBuilder().store(store)
        builder = builder.time(
            datetime.datetime.fromisoformat(validation_time)
        )
        verifier = builder.build_server_verifier(DNSName("cryptography.io"))

        if valid:
            assert verifier.verify(leaf, []) == [leaf]
        else:
            with pytest.raises(
                x509.verification.VerificationError,
                match="cert is not valid at validation time",
            ):
                verifier.verify(leaf, [])
