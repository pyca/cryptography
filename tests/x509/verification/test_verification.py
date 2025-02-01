# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import os
from functools import lru_cache
from ipaddress import IPv4Address

import pytest

from cryptography import x509
from cryptography.hazmat._oid import ExtendedKeyUsageOID
from cryptography.x509.extensions import ExtendedKeyUsage
from cryptography.x509.general_name import DNSName, IPAddress
from cryptography.x509.verification import (
    Criticality,
    ExtensionPolicy,
    Policy,
    PolicyBuilder,
    Store,
    VerificationError,
)
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
            .policy
        )
        assert policy.subject == IPAddress(IPv4Address("0.0.0.0"))

    def test_dnsname_subject(self):
        policy = (
            PolicyBuilder()
            .store(dummy_store())
            .build_server_verifier(DNSName("cryptography.io"))
            .policy
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
        assert verifier.store is store

        policy = verifier.policy
        assert policy.extended_key_usage == ExtendedKeyUsageOID.SERVER_AUTH
        assert policy.max_chain_depth == max_chain_depth
        # this is not currently customizable
        assert policy.minimum_rsa_modulus == 2048
        assert policy.subject == DNSName("cryptography.io")
        assert policy.validation_time == now

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


class TestClientVerifier:
    def test_build_client_verifier_missing_store(self):
        with pytest.raises(
            ValueError, match="A client verifier must have a trust store"
        ):
            PolicyBuilder().build_client_verifier()

    def test_verify(self):
        # expires 2018-11-16 01:15:03 UTC
        leaf = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])

        validation_time = datetime.datetime.fromisoformat(
            "2018-11-16T00:00:00+00:00"
        )
        builder = PolicyBuilder().store(store)
        builder = builder.time(validation_time).max_chain_depth(16)
        verifier = builder.build_client_verifier()

        assert verifier.store is store

        policy = verifier.policy
        assert policy.extended_key_usage == ExtendedKeyUsageOID.CLIENT_AUTH
        assert policy.max_chain_depth == 16
        # this is not currently customizable
        assert policy.minimum_rsa_modulus == 2048
        assert policy.subject is None
        assert policy.validation_time == validation_time.replace(tzinfo=None)

        verified_client = verifier.verify(leaf, [])
        assert verified_client.chain == [leaf]

        assert verified_client.subjects is not None
        assert x509.DNSName("www.cryptography.io") in verified_client.subjects
        assert x509.DNSName("cryptography.io") in verified_client.subjects
        assert len(verified_client.subjects) == 2

    def test_verify_fails_renders_oid(self):
        leaf = _load_cert(
            os.path.join("x509", "custom", "ekucrit-testuser-cert.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])

        validation_time = datetime.datetime.fromisoformat(
            "2024-06-26T00:00:00+00:00"
        )

        builder = PolicyBuilder().store(store)
        builder = builder.time(validation_time)
        verifier = builder.build_client_verifier()

        pattern = (
            r"invalid extension: 2\.5\.29\.37: "
            r"Certificate extension has incorrect criticality"
        )
        with pytest.raises(
            VerificationError,
            match=pattern,
        ):
            verifier.verify(leaf, [])


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

    def test_error_message(self):
        # expires 2018-11-16 01:15:03 UTC
        leaf = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])

        builder = PolicyBuilder().store(store)
        verifier = builder.build_server_verifier(DNSName("cryptography.io"))

        with pytest.raises(
            x509.verification.VerificationError,
            match=r"<Certificate\(subject=.*?CN=www.cryptography.io.*?\)>",
        ):
            verifier.verify(leaf, [])


# TODO: revisit tests


class TestCustomExtensionPolicy:
    leaf = _load_cert(
        os.path.join("x509", "cryptography.io.pem"),
        x509.load_pem_x509_certificate,
    )
    ca = _load_cert(
        os.path.join("x509", "rapidssl_sha256_ca_g3.pem"),
        x509.load_pem_x509_certificate,
    )
    store = Store([ca])
    validation_time = datetime.datetime.fromisoformat(
        "2018-11-16T00:00:00+00:00"
    )

    @staticmethod
    def _eku_validator_cb(policy, cert, ext):
        assert isinstance(policy, Policy)
        assert (
            policy.validation_time
            == TestCustomExtensionPolicy.validation_time.replace(tzinfo=None)
        )
        assert isinstance(cert, x509.Certificate)
        assert ext is None or isinstance(ext, x509.ExtendedKeyUsage)

    def test_custom_cb_pass(self):
        ca_ext_policy = ExtensionPolicy.webpki_defaults_ca()
        ee_ext_policy = ExtensionPolicy.webpki_defaults_ee()

        ee_ext_policy = ee_ext_policy.may_be_present(
            ExtendedKeyUsage.oid, Criticality.AGNOSTIC, self._eku_validator_cb
        )
        ca_ext_policy = ca_ext_policy.may_be_present(
            ExtendedKeyUsage.oid, Criticality.AGNOSTIC, self._eku_validator_cb
        )

        ca_validator_called = False

        def ca_basic_constraints_validator(policy, cert, ext):
            assert cert == self.ca
            assert isinstance(policy, Policy)
            assert isinstance(cert, x509.Certificate)
            assert isinstance(ext, x509.BasicConstraints)
            nonlocal ca_validator_called
            ca_validator_called = True

        ca_ext_policy = ca_ext_policy.may_be_present(
            x509.BasicConstraints.oid,
            Criticality.AGNOSTIC,
            ca_basic_constraints_validator,
        )

        builder = PolicyBuilder().store(self.store)
        builder = builder.time(self.validation_time).max_chain_depth(16)
        builder = builder.extension_policies(ca_ext_policy, ee_ext_policy)

        builder.build_client_verifier().verify(self.leaf, [])
        assert ca_validator_called
        ca_validator_called = False

        path = builder.build_server_verifier(
            DNSName("cryptography.io")
        ).verify(self.leaf, [])
        assert ca_validator_called
        assert path == [self.leaf, self.ca]

    def test_custom_cb_no_retval_enforced(self):
        ca_ext_policy = ExtensionPolicy.webpki_defaults_ca()
        ee_ext_policy = ExtensionPolicy.webpki_defaults_ee()

        def validator(*_):
            return False

        ca_ext_policy = ca_ext_policy.may_be_present(
            x509.BasicConstraints.oid,
            Criticality.AGNOSTIC,
            validator,
        )
        ee_ext_policy = ee_ext_policy.may_be_present(
            ExtendedKeyUsage.oid,
            Criticality.AGNOSTIC,
            validator,
        )

        builder = PolicyBuilder().store(self.store).time(self.validation_time)
        builder = builder.extension_policies(ca_ext_policy, ee_ext_policy)

        for verifier in (
            builder.build_client_verifier(),
            builder.build_server_verifier(DNSName("cryptography.io")),
        ):
            with pytest.raises(
                VerificationError,
                match="Python validator must return None.",
            ):
                verifier.verify(self.leaf, [])

    def test_custom_cb_exception_fails_verification(self):
        ca_ext_policy = ExtensionPolicy.webpki_defaults_ca()
        ee_ext_policy = ExtensionPolicy.webpki_defaults_ee()

        def validator(*_):
            raise ValueError("test")

        ca_ext_policy = ca_ext_policy.may_be_present(
            x509.BasicConstraints.oid,
            Criticality.AGNOSTIC,
            validator,
        )
        ee_ext_policy = ee_ext_policy.may_be_present(
            ExtendedKeyUsage.oid,
            Criticality.AGNOSTIC,
            validator,
        )

        builder = PolicyBuilder().store(self.store).time(self.validation_time)
        builder = builder.extension_policies(ca_ext_policy, ee_ext_policy)

        for verifier in (
            builder.build_client_verifier(),
            builder.build_server_verifier(DNSName("cryptography.io")),
        ):
            with pytest.raises(
                VerificationError,
                match="Python extension validator failed: ValueError: test",
            ):
                verifier.verify(self.leaf, [])
