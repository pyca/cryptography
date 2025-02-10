# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import os
from functools import lru_cache
from ipaddress import IPv4Address
from typing import Optional, Type

import pytest

from cryptography import utils, x509
from cryptography.hazmat._oid import ExtendedKeyUsageOID
from cryptography.x509.extensions import (
    ExtendedKeyUsage,
    ExtensionType,
)
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

WEBPKI_MINIMUM_RSA_MODULUS = 2048


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
        verifier = (
            PolicyBuilder()
            .store(dummy_store())
            .build_server_verifier(IPAddress(IPv4Address("0.0.0.0")))
        )
        assert verifier.policy.subject == IPAddress(IPv4Address("0.0.0.0"))

    def test_dnsname_subject(self):
        verifier = (
            PolicyBuilder()
            .store(dummy_store())
            .build_server_verifier(DNSName("cryptography.io"))
        )
        assert verifier.policy.subject == DNSName("cryptography.io")

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

        subject = DNSName("cryptography.io")
        verifier = builder.build_server_verifier(subject)
        assert verifier.policy.subject == subject
        assert verifier.policy.validation_time == now
        assert verifier.policy.max_chain_depth == max_chain_depth
        with pytest.warns(utils.DeprecatedIn45):
            assert verifier.subject == subject
        with pytest.warns(utils.DeprecatedIn45):
            assert verifier.validation_time == now
        with pytest.warns(utils.DeprecatedIn45):
            assert verifier.max_chain_depth == max_chain_depth

        assert (
            verifier.policy.extended_key_usage
            == ExtendedKeyUsageOID.SERVER_AUTH
        )
        assert (
            verifier.policy.minimum_rsa_modulus == WEBPKI_MINIMUM_RSA_MODULUS
        )
        assert verifier.store == store

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
        max_chain_depth = 16

        builder = PolicyBuilder().store(store)
        builder = builder.time(validation_time).max_chain_depth(
            max_chain_depth
        )
        verifier = builder.build_client_verifier()

        assert verifier.policy.subject is None
        assert verifier.policy.validation_time == validation_time.replace(
            tzinfo=None
        )
        assert verifier.policy.max_chain_depth == max_chain_depth
        with pytest.warns(utils.DeprecatedIn45):
            assert verifier.validation_time == validation_time.replace(
                tzinfo=None
            )
        with pytest.warns(utils.DeprecatedIn45):
            assert verifier.max_chain_depth == max_chain_depth

        assert (
            verifier.policy.extended_key_usage
            == ExtendedKeyUsageOID.CLIENT_AUTH
        )
        assert (
            verifier.policy.minimum_rsa_modulus == WEBPKI_MINIMUM_RSA_MODULUS
        )
        assert verifier.store is store

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

    def test_custom_ext_policy_no_san(self):
        leaf = _load_cert(
            os.path.join("x509", "custom", "no_sans.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])
        validation_time = datetime.datetime.fromisoformat(
            "2025-04-14T00:00:00+00:00"
        )

        builder = PolicyBuilder().store(store)
        builder = builder.time(validation_time)

        with pytest.raises(
            VerificationError,
            match="missing required extension",
        ):
            builder.build_client_verifier().verify(leaf, [])

        ee_extension_policy = ExtensionPolicy.webpki_defaults_ee()
        ee_extension_policy = ee_extension_policy.require_not_present(
            x509.SubjectAlternativeName
        )

        builder = builder.extension_policies(
            ExtensionPolicy.webpki_defaults_ca(), ee_extension_policy
        )

        verified_client = builder.build_client_verifier().verify(leaf, [])
        assert verified_client.subjects is None


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


TESTED_EXTENSION_TYPES = (
    x509.AuthorityInformationAccess,
    x509.AuthorityKeyIdentifier,
    x509.SubjectKeyIdentifier,
    x509.KeyUsage,
    x509.SubjectAlternativeName,
    x509.BasicConstraints,
    x509.NameConstraints,
    x509.ExtendedKeyUsage,
)


class TestCustomExtensionPolicies:
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

    def test_builder_methods(self):
        ext_policy = ExtensionPolicy.permit_all()
        ext_policy = ext_policy.require_not_present(x509.BasicConstraints)
        with pytest.raises(
            ValueError, match=x509.BasicConstraints.oid.dotted_string
        ):
            ext_policy.require_not_present(x509.BasicConstraints)
        with pytest.raises(
            ValueError, match=x509.BasicConstraints.oid.dotted_string
        ):
            ext_policy.may_be_present(
                x509.BasicConstraints, Criticality.NON_CRITICAL, None
            )
        with pytest.raises(
            ValueError, match=x509.BasicConstraints.oid.dotted_string
        ):
            ext_policy.require_present(
                x509.BasicConstraints, Criticality.CRITICAL, None
            )

        with pytest.raises(TypeError):

            class _Extension:
                pass

            ext_policy.require_present(
                _Extension,  # type: ignore
                Criticality.AGNOSTIC,
                None,
            )

    def test_unsupported_extension(self):
        ext_policy = ExtensionPolicy.permit_all()
        message = (
            f"Unsupported extension OID: {x509.Admissions.oid.dotted_string}"
        )
        with pytest.raises(
            ValueError,
            match=message,
        ):
            ext_policy.may_be_present(
                x509.Admissions,
                Criticality.AGNOSTIC,
                None,
            )

    @staticmethod
    def _make_validator_cb(extension_type: Type[ExtensionType]):
        def validator_cb(policy, cert, ext: Optional[ExtensionType]):
            assert isinstance(policy, Policy)
            assert (
                policy.validation_time
                == TestCustomExtensionPolicies.validation_time.replace(
                    tzinfo=None
                )
            )
            assert isinstance(cert, x509.Certificate)
            assert ext is None or isinstance(ext, extension_type)

        return validator_cb

    # def test_all_extension_types(self):
    #     ca_ext_policy = ExtensionPolicy.webpki_defaults_ca()
    #     ee_ext_policy = ExtensionPolicy.webpki_defaults_ee()

    #     ca_validator_called = False

    #     extension_types = [
    #         AuthorityInformationAccess,
    #         AuthorityKeyIdentifier,
    #         SubjectKeyIdentifier,
    #         KeyUsage,
    #         SubjectAlternativeName,
    #         BasicConstraints,
    #     ]

    #     for

    #     ca_ext_policy = ca_ext_policy.may_be_present(
    #         x509.BasicConstraints,
    #         Criticality.AGNOSTIC,
    #         ca_basic_constraints_validator,
    #     )

    #     builder = PolicyBuilder().store(self.store)
    #     builder = builder.time(self.validation_time)
    #     builder = builder.extension_policies(ca_ext_policy, ee_ext_policy)

    #     builder.build_client_verifier().verify(self.leaf, [])

    @pytest.mark.parametrize(
        "extension_type",
        TESTED_EXTENSION_TYPES,
    )
    def test_custom_cb_pass(self, extension_type: Type[x509.ExtensionType]):
        ca_ext_policy = ExtensionPolicy.webpki_defaults_ca()
        ee_ext_policy = ExtensionPolicy.webpki_defaults_ee()

        ee_ext_policy = ee_ext_policy.may_be_present(
            extension_type,
            Criticality.AGNOSTIC,
            self._make_validator_cb(extension_type),
        )

        builder = PolicyBuilder().store(self.store)
        builder = builder.time(self.validation_time).max_chain_depth(16)
        builder = builder.extension_policies(ca_ext_policy, ee_ext_policy)

        builder.build_client_verifier().verify(self.leaf, [])

        path = builder.build_server_verifier(
            DNSName("cryptography.io")
        ).verify(self.leaf, [])
        assert path == [self.leaf, self.ca]

    @pytest.mark.parametrize(
        "extension_type",
        TESTED_EXTENSION_TYPES,
    )
    def test_custom_cb_exception_fails_verification(self, extension_type):
        ca_ext_policy = ExtensionPolicy.webpki_defaults_ca()
        ee_ext_policy = ExtensionPolicy.webpki_defaults_ee()

        def validator(*_):
            raise ValueError("test")

        ca_ext_policy = ca_ext_policy.may_be_present(
            extension_type,
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

    def test_custom_cb_no_retval_enforced(self):
        ca_ext_policy = ExtensionPolicy.webpki_defaults_ca()
        ee_ext_policy = ExtensionPolicy.webpki_defaults_ee()

        def validator(*_):
            return False

        ee_ext_policy = ee_ext_policy.may_be_present(
            ExtendedKeyUsage,
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
