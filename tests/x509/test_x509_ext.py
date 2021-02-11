# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import datetime
import ipaddress
import os
import typing

import pretend

import pytest

from cryptography import x509
from cryptography.hazmat.backends.interfaces import (
    DSABackend,
    EllipticCurveBackend,
    RSABackend,
    X509Backend,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import DNSName, NameConstraints, SubjectAlternativeName
from cryptography.x509.extensions import _key_identifier_from_public_key
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
    ObjectIdentifier,
    SubjectInformationAccessOID,
    _OID_NAMES,
)

from .test_x509 import _load_cert
from ..hazmat.primitives.fixtures_rsa import RSA_KEY_2048
from ..hazmat.primitives.test_ec import _skip_curve_unsupported
from ..utils import load_vectors_from_file


def _make_certbuilder(private_key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.org")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(777)
        .not_valid_before(datetime.datetime(1999, 1, 1))
        .not_valid_after(datetime.datetime(2020, 1, 1))
    )


class TestExtension(object):
    def test_not_an_oid(self):
        bc = x509.BasicConstraints(ca=False, path_length=None)
        with pytest.raises(TypeError):
            x509.Extension("notanoid", True, bc)  # type:ignore[arg-type]

    def test_critical_not_a_bool(self):
        bc = x509.BasicConstraints(ca=False, path_length=None)
        with pytest.raises(TypeError):
            x509.Extension(
                ExtensionOID.BASIC_CONSTRAINTS,
                "notabool",  # type:ignore[arg-type]
                bc,
            )

    def test_repr(self):
        bc = x509.BasicConstraints(ca=False, path_length=None)
        ext = x509.Extension(ExtensionOID.BASIC_CONSTRAINTS, True, bc)
        assert repr(ext) == (
            "<Extension(oid=<ObjectIdentifier(oid=2.5.29.19, name=basicConst"
            "raints)>, critical=True, value=<BasicConstraints(ca=False, path"
            "_length=None)>)>"
        )

    def test_eq(self):
        ext1 = x509.Extension(
            x509.ObjectIdentifier("1.2.3.4"),
            False,
            x509.BasicConstraints(ca=False, path_length=None),
        )
        ext2 = x509.Extension(
            x509.ObjectIdentifier("1.2.3.4"),
            False,
            x509.BasicConstraints(ca=False, path_length=None),
        )
        assert ext1 == ext2

    def test_ne(self):
        ext1 = x509.Extension(
            x509.ObjectIdentifier("1.2.3.4"),
            False,
            x509.BasicConstraints(ca=False, path_length=None),
        )
        ext2 = x509.Extension(
            x509.ObjectIdentifier("1.2.3.5"),
            False,
            x509.BasicConstraints(ca=False, path_length=None),
        )
        ext3 = x509.Extension(
            x509.ObjectIdentifier("1.2.3.4"),
            True,
            x509.BasicConstraints(ca=False, path_length=None),
        )
        ext4 = x509.Extension(
            x509.ObjectIdentifier("1.2.3.4"),
            False,
            x509.BasicConstraints(ca=True, path_length=None),
        )
        assert ext1 != ext2
        assert ext1 != ext3
        assert ext1 != ext4
        assert ext1 != object()

    def test_hash(self):
        ext1 = x509.Extension(
            ExtensionOID.BASIC_CONSTRAINTS,
            False,
            x509.BasicConstraints(ca=False, path_length=None),
        )
        ext2 = x509.Extension(
            ExtensionOID.BASIC_CONSTRAINTS,
            False,
            x509.BasicConstraints(ca=False, path_length=None),
        )
        ext3 = x509.Extension(
            ExtensionOID.BASIC_CONSTRAINTS,
            False,
            x509.BasicConstraints(ca=True, path_length=None),
        )
        assert hash(ext1) == hash(ext2)
        assert hash(ext1) != hash(ext3)


class TestTLSFeature(object):
    def test_not_enum_type(self):
        with pytest.raises(TypeError):
            x509.TLSFeature([3])  # type:ignore[list-item]

    def test_empty_list(self):
        with pytest.raises(TypeError):
            x509.TLSFeature([])

    def test_repr(self):
        ext1 = x509.TLSFeature([x509.TLSFeatureType.status_request])
        assert repr(ext1) == (
            "<TLSFeature(features=[<TLSFeatureType.status_request: 5>])>"
        )

    def test_eq(self):
        ext1 = x509.TLSFeature([x509.TLSFeatureType.status_request])
        ext2 = x509.TLSFeature([x509.TLSFeatureType.status_request])
        assert ext1 == ext2

    def test_ne(self):
        ext1 = x509.TLSFeature([x509.TLSFeatureType.status_request])
        ext2 = x509.TLSFeature([x509.TLSFeatureType.status_request_v2])
        ext3 = x509.TLSFeature(
            [
                x509.TLSFeatureType.status_request,
                x509.TLSFeatureType.status_request_v2,
            ]
        )
        assert ext1 != ext2
        assert ext1 != ext3
        assert ext1 != object()

    def test_hash(self):
        ext1 = x509.TLSFeature([x509.TLSFeatureType.status_request])
        ext2 = x509.TLSFeature([x509.TLSFeatureType.status_request])
        ext3 = x509.TLSFeature(
            [
                x509.TLSFeatureType.status_request,
                x509.TLSFeatureType.status_request_v2,
            ]
        )
        assert hash(ext1) == hash(ext2)
        assert hash(ext1) != hash(ext3)

    def test_iter(self):
        ext1_features = [x509.TLSFeatureType.status_request]
        ext1 = x509.TLSFeature(ext1_features)
        assert len(ext1) == 1
        assert list(ext1) == ext1_features
        ext2_features = [
            x509.TLSFeatureType.status_request,
            x509.TLSFeatureType.status_request_v2,
        ]
        ext2 = x509.TLSFeature(ext2_features)
        assert len(ext2) == 2
        assert list(ext2) == ext2_features

    def test_indexing(self):
        ext = x509.TLSFeature(
            [
                x509.TLSFeatureType.status_request,
                x509.TLSFeatureType.status_request_v2,
            ]
        )
        assert ext[-1] == ext[1]
        assert ext[0] == x509.TLSFeatureType.status_request


class TestUnrecognizedExtension(object):
    def test_invalid_oid(self):
        with pytest.raises(TypeError):
            x509.UnrecognizedExtension(
                "notanoid", b"somedata"  # type:ignore[arg-type]
            )

    def test_eq(self):
        ext1 = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x01"
        )
        ext2 = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x01"
        )
        assert ext1 == ext2

    def test_ne(self):
        ext1 = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x01"
        )
        ext2 = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x02"
        )
        ext3 = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.2.3.5"), b"\x03\x02\x01"
        )
        assert ext1 != ext2
        assert ext1 != ext3
        assert ext1 != object()

    def test_repr(self):
        ext1 = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x01"
        )
        assert repr(ext1) == (
            "<UnrecognizedExtension(oid=<ObjectIdentifier(oid=1.2.3.4, "
            "name=Unknown OID)>, value=b'\\x03\\x02\\x01')>"
        )

    def test_hash(self):
        ext1 = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x01"
        )
        ext2 = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x01"
        )
        ext3 = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.2.3.5"), b"\x03\x02\x01"
        )
        assert hash(ext1) == hash(ext2)
        assert hash(ext1) != hash(ext3)


class TestCertificateIssuer(object):
    def test_iter_names(self):
        ci = x509.CertificateIssuer(
            [x509.DNSName("cryptography.io"), x509.DNSName("crypto.local")]
        )
        assert len(ci) == 2
        assert list(ci) == [
            x509.DNSName("cryptography.io"),
            x509.DNSName("crypto.local"),
        ]

    def test_indexing(self):
        ci = x509.CertificateIssuer(
            [
                x509.DNSName("cryptography.io"),
                x509.DNSName("crypto.local"),
                x509.DNSName("another.local"),
                x509.RFC822Name("email@another.local"),
                x509.UniformResourceIdentifier("http://another.local"),
            ]
        )
        assert ci[-1] == ci[4]
        assert ci[2:6:2] == [ci[2], ci[4]]

    def test_eq(self):
        ci1 = x509.CertificateIssuer([x509.DNSName("cryptography.io")])
        ci2 = x509.CertificateIssuer([x509.DNSName("cryptography.io")])
        assert ci1 == ci2

    def test_ne(self):
        ci1 = x509.CertificateIssuer([x509.DNSName("cryptography.io")])
        ci2 = x509.CertificateIssuer([x509.DNSName("somethingelse.tld")])
        assert ci1 != ci2
        assert ci1 != object()

    def test_repr(self):
        ci = x509.CertificateIssuer([x509.DNSName("cryptography.io")])
        assert repr(ci) == (
            "<CertificateIssuer(<GeneralNames([<DNSName(value="
            "'cryptography.io')>])>)>"
        )

    def test_get_values_for_type(self):
        ci = x509.CertificateIssuer([x509.DNSName("cryptography.io")])
        names = ci.get_values_for_type(x509.DNSName)
        assert names == ["cryptography.io"]

    def test_hash(self):
        ci1 = x509.CertificateIssuer([x509.DNSName("cryptography.io")])
        ci2 = x509.CertificateIssuer([x509.DNSName("cryptography.io")])
        ci3 = x509.CertificateIssuer(
            [x509.UniformResourceIdentifier("http://something")]
        )
        assert hash(ci1) == hash(ci2)
        assert hash(ci1) != hash(ci3)


class TestCRLReason(object):
    def test_invalid_reason_flags(self):
        with pytest.raises(TypeError):
            x509.CRLReason("notareason")  # type:ignore[arg-type]

    def test_eq(self):
        reason1 = x509.CRLReason(x509.ReasonFlags.unspecified)
        reason2 = x509.CRLReason(x509.ReasonFlags.unspecified)
        assert reason1 == reason2

    def test_ne(self):
        reason1 = x509.CRLReason(x509.ReasonFlags.unspecified)
        reason2 = x509.CRLReason(x509.ReasonFlags.ca_compromise)
        assert reason1 != reason2
        assert reason1 != object()

    def test_hash(self):
        reason1 = x509.CRLReason(x509.ReasonFlags.unspecified)
        reason2 = x509.CRLReason(x509.ReasonFlags.unspecified)
        reason3 = x509.CRLReason(x509.ReasonFlags.ca_compromise)

        assert hash(reason1) == hash(reason2)
        assert hash(reason1) != hash(reason3)

    def test_repr(self):
        reason1 = x509.CRLReason(x509.ReasonFlags.unspecified)
        assert repr(reason1) == ("<CRLReason(reason=ReasonFlags.unspecified)>")


class TestDeltaCRLIndicator(object):
    def test_not_int(self):
        with pytest.raises(TypeError):
            x509.DeltaCRLIndicator("notanint")  # type:ignore[arg-type]

    def test_eq(self):
        delta1 = x509.DeltaCRLIndicator(1)
        delta2 = x509.DeltaCRLIndicator(1)
        assert delta1 == delta2

    def test_ne(self):
        delta1 = x509.DeltaCRLIndicator(1)
        delta2 = x509.DeltaCRLIndicator(2)
        assert delta1 != delta2
        assert delta1 != object()

    def test_repr(self):
        delta1 = x509.DeltaCRLIndicator(2)
        assert repr(delta1) == ("<DeltaCRLIndicator(crl_number=2)>")

    def test_hash(self):
        delta1 = x509.DeltaCRLIndicator(1)
        delta2 = x509.DeltaCRLIndicator(1)
        delta3 = x509.DeltaCRLIndicator(2)
        assert hash(delta1) == hash(delta2)
        assert hash(delta1) != hash(delta3)


class TestInvalidityDate(object):
    def test_invalid_invalidity_date(self):
        with pytest.raises(TypeError):
            x509.InvalidityDate("notadate")  # type:ignore[arg-type]

    def test_eq(self):
        invalid1 = x509.InvalidityDate(datetime.datetime(2015, 1, 1, 1, 1))
        invalid2 = x509.InvalidityDate(datetime.datetime(2015, 1, 1, 1, 1))
        assert invalid1 == invalid2

    def test_ne(self):
        invalid1 = x509.InvalidityDate(datetime.datetime(2015, 1, 1, 1, 1))
        invalid2 = x509.InvalidityDate(datetime.datetime(2015, 1, 1, 1, 2))
        assert invalid1 != invalid2
        assert invalid1 != object()

    def test_repr(self):
        invalid1 = x509.InvalidityDate(datetime.datetime(2015, 1, 1, 1, 1))
        assert repr(invalid1) == (
            "<InvalidityDate(invalidity_date=2015-01-01 01:01:00)>"
        )

    def test_hash(self):
        invalid1 = x509.InvalidityDate(datetime.datetime(2015, 1, 1, 1, 1))
        invalid2 = x509.InvalidityDate(datetime.datetime(2015, 1, 1, 1, 1))
        invalid3 = x509.InvalidityDate(datetime.datetime(2015, 1, 1, 1, 2))
        assert hash(invalid1) == hash(invalid2)
        assert hash(invalid1) != hash(invalid3)


class TestNoticeReference(object):
    def test_notice_numbers_not_all_int(self):
        with pytest.raises(TypeError):
            x509.NoticeReference(
                "org", [1, 2, "three"]  # type:ignore[list-item]
            )

    def test_notice_numbers_none(self):
        with pytest.raises(TypeError):
            x509.NoticeReference("org", None)  # type:ignore[arg-type]

    def test_iter_input(self):
        numbers = [1, 3, 4]
        nr = x509.NoticeReference("org", iter(numbers))
        assert list(nr.notice_numbers) == numbers

    def test_repr(self):
        nr = x509.NoticeReference("org", [1, 3, 4])

        assert repr(nr) == (
            "<NoticeReference(organization='org', notice_numbers=[1, 3, 4"
            "])>"
        )

    def test_eq(self):
        nr = x509.NoticeReference("org", [1, 2])
        nr2 = x509.NoticeReference("org", [1, 2])
        assert nr == nr2

    def test_ne(self):
        nr = x509.NoticeReference("org", [1, 2])
        nr2 = x509.NoticeReference("org", [1])
        nr3 = x509.NoticeReference(None, [1, 2])
        assert nr != nr2
        assert nr != nr3
        assert nr != object()

    def test_hash(self):
        nr = x509.NoticeReference("org", [1, 2])
        nr2 = x509.NoticeReference("org", [1, 2])
        nr3 = x509.NoticeReference(None, [1, 2])
        assert hash(nr) == hash(nr2)
        assert hash(nr) != hash(nr3)


class TestUserNotice(object):
    def test_notice_reference_invalid(self):
        with pytest.raises(TypeError):
            x509.UserNotice("invalid", None)  # type:ignore[arg-type]

    def test_notice_reference_none(self):
        un = x509.UserNotice(None, "text")
        assert un.notice_reference is None
        assert un.explicit_text == "text"

    def test_repr(self):
        un = x509.UserNotice(x509.NoticeReference("org", [1]), "text")
        assert repr(un) == (
            "<UserNotice(notice_reference=<NoticeReference(organization='"
            "org', notice_numbers=[1])>, explicit_text='text')>"
        )

    def test_eq(self):
        nr = x509.NoticeReference("org", [1, 2])
        nr2 = x509.NoticeReference("org", [1, 2])
        un = x509.UserNotice(nr, "text")
        un2 = x509.UserNotice(nr2, "text")
        assert un == un2

    def test_ne(self):
        nr = x509.NoticeReference("org", [1, 2])
        nr2 = x509.NoticeReference("org", [1])
        un = x509.UserNotice(nr, "text")
        un2 = x509.UserNotice(nr2, "text")
        un3 = x509.UserNotice(nr, "text3")
        assert un != un2
        assert un != un3
        assert un != object()

    def test_hash(self):
        nr = x509.NoticeReference("org", [1, 2])
        nr2 = x509.NoticeReference("org", [1, 2])
        un = x509.UserNotice(nr, "text")
        un2 = x509.UserNotice(nr2, "text")
        un3 = x509.UserNotice(None, "text")
        assert hash(un) == hash(un2)
        assert hash(un) != hash(un3)


class TestPolicyInformation(object):
    def test_invalid_policy_identifier(self):
        with pytest.raises(TypeError):
            x509.PolicyInformation("notanoid", None)  # type:ignore[arg-type]

    def test_none_policy_qualifiers(self):
        pi = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), None)
        assert pi.policy_identifier == x509.ObjectIdentifier("1.2.3")
        assert pi.policy_qualifiers is None

    def test_policy_qualifiers(self):
        pq = ["string"]
        pi = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), pq)
        assert pi.policy_identifier == x509.ObjectIdentifier("1.2.3")
        assert pi.policy_qualifiers == pq

    def test_invalid_policy_identifiers(self):
        with pytest.raises(TypeError):
            x509.PolicyInformation(
                x509.ObjectIdentifier("1.2.3"),
                [1, 2],  # type:ignore[list-item]
            )

    def test_iter_input(self):
        qual = ["foo", "bar"]
        pi = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), iter(qual))
        assert list(pi.policy_qualifiers) == qual

    def test_repr(self):
        pq: typing.List[typing.Union[str, x509.UserNotice]] = [
            "string",
            x509.UserNotice(None, "hi"),
        ]
        pi = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), pq)
        assert repr(pi) == (
            "<PolicyInformation(policy_identifier=<ObjectIdentifier(oid=1."
            "2.3, name=Unknown OID)>, policy_qualifiers=['string', <UserNo"
            "tice(notice_reference=None, explicit_text='hi')>])>"
        )

    def test_eq(self):
        pi = x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.3"),
            ["string", x509.UserNotice(None, "hi")],
        )
        pi2 = x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.3"),
            ["string", x509.UserNotice(None, "hi")],
        )
        assert pi == pi2

    def test_ne(self):
        pi = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), ["string"])
        pi2 = x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.3"), ["string2"]
        )
        pi3 = x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.3.4"), ["string"]
        )
        assert pi != pi2
        assert pi != pi3
        assert pi != object()

    def test_hash(self):
        pi = x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.3"),
            ["string", x509.UserNotice(None, "hi")],
        )
        pi2 = x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.3"),
            ["string", x509.UserNotice(None, "hi")],
        )
        pi3 = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), None)
        assert hash(pi) == hash(pi2)
        assert hash(pi) != hash(pi3)


@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestCertificatePolicies(object):
    def test_invalid_policies(self):
        pq = ["string"]
        pi = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), pq)
        with pytest.raises(TypeError):
            x509.CertificatePolicies([1, pi])  # type:ignore[list-item]

    def test_iter_len(self):
        pq = ["string"]
        pi = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), pq)
        cp = x509.CertificatePolicies([pi])
        assert len(cp) == 1
        for policyinfo in cp:
            assert policyinfo == pi

    def test_iter_input(self):
        policies = [
            x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), ["string"])
        ]
        cp = x509.CertificatePolicies(iter(policies))
        assert list(cp) == policies

    def test_repr(self):
        pq = ["string"]
        pi = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), pq)
        cp = x509.CertificatePolicies([pi])
        assert repr(cp) == (
            "<CertificatePolicies([<PolicyInformation(policy_identifier=<O"
            "bjectIdentifier(oid=1.2.3, name=Unknown OID)>, policy_qualifi"
            "ers=['string'])>])>"
        )

    def test_eq(self):
        pi = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), ["string"])
        cp = x509.CertificatePolicies([pi])
        pi2 = x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.3"), ["string"]
        )
        cp2 = x509.CertificatePolicies([pi2])
        assert cp == cp2

    def test_ne(self):
        pi = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), ["string"])
        cp = x509.CertificatePolicies([pi])
        pi2 = x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.3"), ["string2"]
        )
        cp2 = x509.CertificatePolicies([pi2])
        assert cp != cp2
        assert cp != object()

    def test_indexing(self):
        pi = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), ["test"])
        pi2 = x509.PolicyInformation(x509.ObjectIdentifier("1.2.4"), ["test"])
        pi3 = x509.PolicyInformation(x509.ObjectIdentifier("1.2.5"), ["test"])
        pi4 = x509.PolicyInformation(x509.ObjectIdentifier("1.2.6"), ["test"])
        pi5 = x509.PolicyInformation(x509.ObjectIdentifier("1.2.7"), ["test"])
        cp = x509.CertificatePolicies([pi, pi2, pi3, pi4, pi5])
        assert cp[-1] == cp[4]
        assert cp[2:6:2] == [cp[2], cp[4]]

    def test_long_oid(self, backend):
        """
        Test that parsing a CertificatePolicies ext with
        a very long OID succeeds.
        """
        cert = _load_cert(
            os.path.join("x509", "bigoid.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_class(x509.CertificatePolicies)

        oid = x509.ObjectIdentifier(
            "1.3.6.1.4.1.311.21.8.8950086.10656446.2706058"
            ".12775672.480128.147.13466065.13029902"
        )

        assert ext.value[0].policy_identifier == oid

    def test_hash(self):
        pi = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), ["string"])
        cp = x509.CertificatePolicies([pi])
        pi2 = x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.3"), ["string"]
        )
        cp2 = x509.CertificatePolicies([pi2])
        pi3 = x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.3"), [x509.UserNotice(None, "text")]
        )
        cp3 = x509.CertificatePolicies([pi3])
        assert hash(cp) == hash(cp2)
        assert hash(cp) != hash(cp3)


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestCertificatePoliciesExtension(object):
    def test_cps_uri_policy_qualifier(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "cp_cps_uri.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )

        cp = cert.extensions.get_extension_for_oid(
            ExtensionOID.CERTIFICATE_POLICIES
        ).value

        assert cp == x509.CertificatePolicies(
            [
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.16.840.1.12345.1.2.3.4.1"),
                    ["http://other.com/cps"],
                )
            ]
        )

    def test_user_notice_with_notice_reference(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom", "cp_user_notice_with_notice_reference.pem"
            ),
            x509.load_pem_x509_certificate,
            backend,
        )

        cp = cert.extensions.get_extension_for_oid(
            ExtensionOID.CERTIFICATE_POLICIES
        ).value

        assert cp == x509.CertificatePolicies(
            [
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.16.840.1.12345.1.2.3.4.1"),
                    [
                        "http://example.com/cps",
                        "http://other.com/cps",
                        x509.UserNotice(
                            x509.NoticeReference("my org", [1, 2, 3, 4]),
                            "thing",
                        ),
                    ],
                )
            ]
        )

    def test_user_notice_with_explicit_text(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom", "cp_user_notice_with_explicit_text.pem"
            ),
            x509.load_pem_x509_certificate,
            backend,
        )

        cp = cert.extensions.get_extension_for_oid(
            ExtensionOID.CERTIFICATE_POLICIES
        ).value

        assert cp == x509.CertificatePolicies(
            [
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.16.840.1.12345.1.2.3.4.1"),
                    [x509.UserNotice(None, "thing")],
                )
            ]
        )

    def test_user_notice_no_explicit_text(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom", "cp_user_notice_no_explicit_text.pem"
            ),
            x509.load_pem_x509_certificate,
            backend,
        )

        cp = cert.extensions.get_extension_for_oid(
            ExtensionOID.CERTIFICATE_POLICIES
        ).value

        assert cp == x509.CertificatePolicies(
            [
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.16.840.1.12345.1.2.3.4.1"),
                    [
                        x509.UserNotice(
                            x509.NoticeReference("my org", [1, 2, 3, 4]), None
                        )
                    ],
                )
            ]
        )


class TestKeyUsage(object):
    def test_key_agreement_false_encipher_decipher_true(self):
        with pytest.raises(ValueError):
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=True,
                decipher_only=False,
            )

        with pytest.raises(ValueError):
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=True,
                decipher_only=True,
            )

        with pytest.raises(ValueError):
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=True,
            )

    def test_properties_key_agreement_true(self):
        ku = x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        assert ku.digital_signature is True
        assert ku.content_commitment is True
        assert ku.key_encipherment is False
        assert ku.data_encipherment is False
        assert ku.key_agreement is False
        assert ku.key_cert_sign is True
        assert ku.crl_sign is False

    def test_key_agreement_true_properties(self):
        ku = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=True,
        )
        assert ku.key_agreement is True
        assert ku.encipher_only is False
        assert ku.decipher_only is True

    def test_key_agreement_false_properties(self):
        ku = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        assert ku.key_agreement is False
        with pytest.raises(ValueError):
            ku.encipher_only

        with pytest.raises(ValueError):
            ku.decipher_only

    def test_repr_key_agreement_false(self):
        ku = x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        assert repr(ku) == (
            "<KeyUsage(digital_signature=True, content_commitment=True, key_en"
            "cipherment=False, data_encipherment=False, key_agreement=False, k"
            "ey_cert_sign=True, crl_sign=False, encipher_only=False, decipher_"
            "only=False)>"
        )

    def test_repr_key_agreement_true(self):
        ku = x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        assert repr(ku) == (
            "<KeyUsage(digital_signature=True, content_commitment=True, key_en"
            "cipherment=False, data_encipherment=False, key_agreement=True, k"
            "ey_cert_sign=True, crl_sign=False, encipher_only=False, decipher_"
            "only=False)>"
        )

    def test_eq(self):
        ku = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=True,
        )
        ku2 = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=True,
        )
        assert ku == ku2

    def test_ne(self):
        ku = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=True,
        )
        ku2 = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        assert ku != ku2
        assert ku != object()

    def test_hash(self):
        ku = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=True,
        )
        ku2 = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=True,
        )
        ku3 = x509.KeyUsage(
            digital_signature=False,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        assert hash(ku) == hash(ku2)
        assert hash(ku) != hash(ku3)


class TestSubjectKeyIdentifier(object):
    def test_properties(self):
        value = binascii.unhexlify(b"092384932230498bc980aa8098456f6ff7ff3ac9")
        ski = x509.SubjectKeyIdentifier(value)
        assert ski.digest == value

    def test_repr(self):
        ski = x509.SubjectKeyIdentifier(
            binascii.unhexlify(b"092384932230498bc980aa8098456f6ff7ff3ac9")
        )
        ext = x509.Extension(ExtensionOID.SUBJECT_KEY_IDENTIFIER, False, ski)
        assert repr(ext) == (
            "<Extension(oid=<ObjectIdentifier(oid=2.5.29.14, name=subjectK"
            "eyIdentifier)>, critical=False, value=<SubjectKeyIdentifier(d"
            "igest=b'\\t#\\x84\\x93\"0I\\x8b\\xc9\\x80\\xaa\\x80\\x98Eoo"
            "\\xf7\\xff:\\xc9')>)>"
        )

    def test_eq(self):
        ski = x509.SubjectKeyIdentifier(
            binascii.unhexlify(b"092384932230498bc980aa8098456f6ff7ff3ac9")
        )
        ski2 = x509.SubjectKeyIdentifier(
            binascii.unhexlify(b"092384932230498bc980aa8098456f6ff7ff3ac9")
        )
        assert ski == ski2

    def test_ne(self):
        ski = x509.SubjectKeyIdentifier(
            binascii.unhexlify(b"092384932230498bc980aa8098456f6ff7ff3ac9")
        )
        ski2 = x509.SubjectKeyIdentifier(
            binascii.unhexlify(b"aa8098456f6ff7ff3ac9092384932230498bc980")
        )
        assert ski != ski2
        assert ski != object()

    def test_hash(self):
        ski1 = x509.SubjectKeyIdentifier(
            binascii.unhexlify(b"092384932230498bc980aa8098456f6ff7ff3ac9")
        )
        ski2 = x509.SubjectKeyIdentifier(
            binascii.unhexlify(b"092384932230498bc980aa8098456f6ff7ff3ac9")
        )
        ski3 = x509.SubjectKeyIdentifier(
            binascii.unhexlify(b"aa8098456f6ff7ff3ac9092384932230498bc980")
        )
        assert hash(ski1) == hash(ski2)
        assert hash(ski1) != hash(ski3)


class TestAuthorityKeyIdentifier(object):
    def test_authority_cert_issuer_not_generalname(self):
        with pytest.raises(TypeError):
            x509.AuthorityKeyIdentifier(
                b"identifier", ["notname"], 3  # type:ignore[list-item]
            )

    def test_authority_cert_serial_number_not_integer(self):
        dirname = x509.DirectoryName(
            x509.Name(
                [
                    x509.NameAttribute(
                        x509.ObjectIdentifier("2.999.1"), "value1"
                    ),
                    x509.NameAttribute(
                        x509.ObjectIdentifier("2.999.2"), "value2"
                    ),
                ]
            )
        )
        with pytest.raises(TypeError):
            x509.AuthorityKeyIdentifier(
                b"identifier", [dirname], "notanint"  # type:ignore[arg-type]
            )

    def test_authority_issuer_none_serial_not_none(self):
        with pytest.raises(ValueError):
            x509.AuthorityKeyIdentifier(b"identifier", None, 3)

    def test_authority_issuer_not_none_serial_none(self):
        dirname = x509.DirectoryName(
            x509.Name(
                [
                    x509.NameAttribute(
                        x509.ObjectIdentifier("2.999.1"), "value1"
                    ),
                    x509.NameAttribute(
                        x509.ObjectIdentifier("2.999.2"), "value2"
                    ),
                ]
            )
        )
        with pytest.raises(ValueError):
            x509.AuthorityKeyIdentifier(b"identifier", [dirname], None)

    def test_authority_cert_serial_and_issuer_none(self):
        aki = x509.AuthorityKeyIdentifier(b"id", None, None)
        assert aki.key_identifier == b"id"
        assert aki.authority_cert_issuer is None
        assert aki.authority_cert_serial_number is None

    def test_authority_cert_serial_zero(self):
        dns = x509.DNSName("SomeIssuer")
        aki = x509.AuthorityKeyIdentifier(b"id", [dns], 0)
        assert aki.key_identifier == b"id"
        assert aki.authority_cert_issuer == [dns]
        assert aki.authority_cert_serial_number == 0

    def test_iter_input(self):
        dirnames = [
            x509.DirectoryName(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "myCN")])
            )
        ]
        aki = x509.AuthorityKeyIdentifier(b"digest", iter(dirnames), 1234)
        assert list(aki.authority_cert_issuer) == dirnames

    def test_repr(self):
        dirname = x509.DirectoryName(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "myCN")])
        )
        aki = x509.AuthorityKeyIdentifier(b"digest", [dirname], 1234)

        assert repr(aki) == (
            "<AuthorityKeyIdentifier(key_identifier=b'digest', authority_"
            "cert_issuer=[<DirectoryName(value=<Name(CN=myCN)>)>], author"
            "ity_cert_serial_number=1234)>"
        )

    def test_eq(self):
        dirname = x509.DirectoryName(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "myCN")])
        )
        aki = x509.AuthorityKeyIdentifier(b"digest", [dirname], 1234)
        dirname2 = x509.DirectoryName(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "myCN")])
        )
        aki2 = x509.AuthorityKeyIdentifier(b"digest", [dirname2], 1234)
        assert aki == aki2

    def test_ne(self):
        dirname = x509.DirectoryName(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "myCN")])
        )
        dirname5 = x509.DirectoryName(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aCN")])
        )
        aki = x509.AuthorityKeyIdentifier(b"digest", [dirname], 1234)
        aki2 = x509.AuthorityKeyIdentifier(b"diges", [dirname], 1234)
        aki3 = x509.AuthorityKeyIdentifier(b"digest", None, None)
        aki4 = x509.AuthorityKeyIdentifier(b"digest", [dirname], 12345)
        aki5 = x509.AuthorityKeyIdentifier(b"digest", [dirname5], 12345)
        assert aki != aki2
        assert aki != aki3
        assert aki != aki4
        assert aki != aki5
        assert aki != object()

    def test_hash(self):
        dirname = x509.DirectoryName(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "myCN")])
        )
        aki1 = x509.AuthorityKeyIdentifier(b"digest", [dirname], 1234)
        aki2 = x509.AuthorityKeyIdentifier(b"digest", [dirname], 1234)
        aki3 = x509.AuthorityKeyIdentifier(b"digest", None, None)
        assert hash(aki1) == hash(aki2)
        assert hash(aki1) != hash(aki3)


class TestBasicConstraints(object):
    def test_ca_not_boolean(self):
        with pytest.raises(TypeError):
            x509.BasicConstraints(
                ca="notbool", path_length=None  # type:ignore[arg-type]
            )

    def test_path_length_not_ca(self):
        with pytest.raises(ValueError):
            x509.BasicConstraints(ca=False, path_length=0)

    def test_path_length_not_int(self):
        with pytest.raises(TypeError):
            x509.BasicConstraints(
                ca=True, path_length=1.1  # type:ignore[arg-type]
            )

        with pytest.raises(TypeError):
            x509.BasicConstraints(
                ca=True, path_length="notint"  # type:ignore[arg-type]
            )

    def test_path_length_negative(self):
        with pytest.raises(TypeError):
            x509.BasicConstraints(ca=True, path_length=-1)

    def test_repr(self):
        na = x509.BasicConstraints(ca=True, path_length=None)
        assert repr(na) == ("<BasicConstraints(ca=True, path_length=None)>")

    def test_hash(self):
        na = x509.BasicConstraints(ca=True, path_length=None)
        na2 = x509.BasicConstraints(ca=True, path_length=None)
        na3 = x509.BasicConstraints(ca=True, path_length=0)
        assert hash(na) == hash(na2)
        assert hash(na) != hash(na3)

    def test_eq(self):
        na = x509.BasicConstraints(ca=True, path_length=None)
        na2 = x509.BasicConstraints(ca=True, path_length=None)
        assert na == na2

    def test_ne(self):
        na = x509.BasicConstraints(ca=True, path_length=None)
        na2 = x509.BasicConstraints(ca=True, path_length=1)
        na3 = x509.BasicConstraints(ca=False, path_length=None)
        assert na != na2
        assert na != na3
        assert na != object()


class TestExtendedKeyUsage(object):
    def test_not_all_oids(self):
        with pytest.raises(TypeError):
            x509.ExtendedKeyUsage(["notoid"])  # type:ignore[list-item]

    def test_iter_len(self):
        eku = x509.ExtendedKeyUsage(
            [
                x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1"),
                x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2"),
            ]
        )
        assert len(eku) == 2
        assert list(eku) == [
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]

    def test_iter_input(self):
        usages = [
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1"),
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2"),
        ]
        aia = x509.ExtendedKeyUsage(iter(usages))
        assert list(aia) == usages

    def test_repr(self):
        eku = x509.ExtendedKeyUsage(
            [
                x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1"),
                x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2"),
            ]
        )
        assert repr(eku) == (
            "<ExtendedKeyUsage([<ObjectIdentifier(oid=1.3.6.1.5.5.7.3.1, name="
            "serverAuth)>, <ObjectIdentifier(oid=1.3.6.1.5.5.7.3.2, name=clien"
            "tAuth)>])>"
        )

    def test_eq(self):
        eku = x509.ExtendedKeyUsage(
            [x509.ObjectIdentifier("1.3.6"), x509.ObjectIdentifier("1.3.7")]
        )
        eku2 = x509.ExtendedKeyUsage(
            [x509.ObjectIdentifier("1.3.6"), x509.ObjectIdentifier("1.3.7")]
        )
        assert eku == eku2

    def test_ne(self):
        eku = x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6")])
        eku2 = x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1")])
        assert eku != eku2
        assert eku != object()

    def test_hash(self):
        eku = x509.ExtendedKeyUsage(
            [x509.ObjectIdentifier("1.3.6"), x509.ObjectIdentifier("1.3.7")]
        )
        eku2 = x509.ExtendedKeyUsage(
            [x509.ObjectIdentifier("1.3.6"), x509.ObjectIdentifier("1.3.7")]
        )
        eku3 = x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6")])
        assert hash(eku) == hash(eku2)
        assert hash(eku) != hash(eku3)


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestExtensions(object):
    def test_no_extensions(self, backend):
        cert = _load_cert(
            os.path.join("x509", "verisign_md2_root.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions
        assert len(ext) == 0
        assert list(ext) == []
        with pytest.raises(x509.ExtensionNotFound) as exc:
            ext.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)

        assert exc.value.oid == ExtensionOID.BASIC_CONSTRAINTS

    def test_one_extension(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom", "basic_constraints_not_critical.pem"
            ),
            x509.load_pem_x509_certificate,
            backend,
        )
        extensions = cert.extensions
        ext = extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        assert ext is not None
        assert ext.value.ca is False

    def test_duplicate_extension(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "two_basic_constraints.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        with pytest.raises(x509.DuplicateExtension) as exc:
            cert.extensions

        assert exc.value.oid == ExtensionOID.BASIC_CONSTRAINTS

    def test_unsupported_critical_extension(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom", "unsupported_extension_critical.pem"
            ),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier("1.2.3.4")
        )
        assert ext.value.value == b"value"

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    def test_unsupported_extension(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "unsupported_extension_2.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        extensions = cert.extensions
        assert len(extensions) == 2
        assert extensions[0].critical is False
        assert extensions[0].oid == x509.ObjectIdentifier(
            "1.3.6.1.4.1.41482.2"
        )
        assert extensions[0].value == x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.3.6.1.4.1.41482.2"),
            b"1.3.6.1.4.1.41482.1.2",
        )
        assert extensions[1].critical is False
        assert extensions[1].oid == x509.ObjectIdentifier(
            "1.3.6.1.4.1.45724.2.1.1"
        )
        assert extensions[1].value == x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.3.6.1.4.1.45724.2.1.1"), b"\x03\x02\x040"
        )

    def test_no_extensions_get_for_class(self, backend):
        cert = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        exts = cert.extensions
        with pytest.raises(x509.ExtensionNotFound) as exc:
            exts.get_extension_for_class(x509.IssuerAlternativeName)
        assert exc.value.oid == ExtensionOID.ISSUER_ALTERNATIVE_NAME

    def test_unrecognized_extension_for_class(self):
        exts = x509.Extensions([])
        with pytest.raises(TypeError):
            exts.get_extension_for_class(x509.UnrecognizedExtension)

    def test_indexing(self, backend):
        cert = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        exts = cert.extensions
        assert exts[-1] == exts[7]
        assert exts[2:6:2] == [exts[2], exts[4]]

    def test_one_extension_get_for_class(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom", "basic_constraints_not_critical.pem"
            ),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert ext is not None
        assert isinstance(ext.value, x509.BasicConstraints)

    def test_repr(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom", "basic_constraints_not_critical.pem"
            ),
            x509.load_pem_x509_certificate,
            backend,
        )
        assert repr(cert.extensions) == (
            "<Extensions([<Extension(oid=<ObjectIdentifier(oid=2.5.29.19, name"
            "=basicConstraints)>, critical=False, value=<BasicConstraints(ca=F"
            "alse, path_length=None)>)>])>"
        )


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestBasicConstraintsExtension(object):
    def test_ca_true_pathlen_6(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs", "pathLenConstraint6CACert.crt"
            ),
            x509.load_der_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert ext is not None
        assert ext.critical is True
        assert ext.value.ca is True
        assert ext.value.path_length == 6

    def test_path_length_zero(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "bc_path_length_zero.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert ext is not None
        assert ext.critical is True
        assert ext.value.ca is True
        assert ext.value.path_length == 0

    def test_ca_true_no_pathlen(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert ext is not None
        assert ext.critical is True
        assert ext.value.ca is True
        assert ext.value.path_length is None

    def test_ca_false(self, backend):
        cert = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert ext is not None
        assert ext.critical is True
        assert ext.value.ca is False
        assert ext.value.path_length is None

    def test_no_basic_constraints(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509",
                "PKITS_data",
                "certs",
                "ValidCertificatePathTest1EE.crt",
            ),
            x509.load_der_x509_certificate,
            backend,
        )
        with pytest.raises(x509.ExtensionNotFound):
            cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )

    def test_basic_constraint_not_critical(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom", "basic_constraints_not_critical.pem"
            ),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert ext is not None
        assert ext.critical is False
        assert ext.value.ca is False


class TestSubjectKeyIdentifierExtension(object):
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_subject_key_identifier(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        ski = ext.value
        assert ext is not None
        assert ext.critical is False
        assert ski.digest == binascii.unhexlify(
            b"580184241bbc2b52944a3da510721451f5af3ac9"
        )

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_subject_key_identifier(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "bc_path_length_zero.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        with pytest.raises(x509.ExtensionNotFound):
            cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_KEY_IDENTIFIER
            )

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_from_rsa_public_key(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key())
        assert ext.value == ski

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_from_dsa_public_key(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "dsa_selfsigned_ca.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key())
        assert ext.value == ski

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_invalid_bit_string_padding_from_public_key(self, backend):
        data = load_vectors_from_file(
            filename=os.path.join(
                "asymmetric",
                "DER_Serialization",
                "dsa_public_key_invalid_bit_string.der",
            ),
            loader=lambda data: data.read(),
            mode="rb",
        )
        pretend_key = pretend.stub(public_bytes=lambda x, y: data)
        with pytest.raises(ValueError):
            _key_identifier_from_public_key(pretend_key)

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_optional_params_allowed_from_public_key(self, backend):
        data = load_vectors_from_file(
            filename=os.path.join(
                "asymmetric",
                "DER_Serialization",
                "dsa_public_key_no_params.der",
            ),
            loader=lambda data: data.read(),
            mode="rb",
        )
        pretend_key = pretend.stub(public_bytes=lambda x, y: data)
        key_identifier = _key_identifier_from_public_key(pretend_key)
        assert key_identifier == binascii.unhexlify(
            b"24c0133a6a492f2c48a18c7648e515db5ac76749"
        )

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_from_ec_public_key(self, backend):
        _skip_curve_unsupported(backend, ec.SECP384R1())
        cert = _load_cert(
            os.path.join("x509", "ecdsa_root.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key())
        assert ext.value == ski

    @pytest.mark.supported(
        only_if=lambda backend: backend.ed25519_supported(),
        skip_message="Requires OpenSSL with Ed25519 support",
    )
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_from_ed25519_public_key(self, backend):
        cert = _load_cert(
            os.path.join("x509", "ed25519", "root-ed25519.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key())
        assert ext.value == ski

    @pytest.mark.supported(
        only_if=lambda backend: backend.ed448_supported(),
        skip_message="Requires OpenSSL with Ed448 support",
    )
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_from_ed448_public_key(self, backend):
        cert = _load_cert(
            os.path.join("x509", "ed448", "root-ed448.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key())
        assert ext.value == ski


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestKeyUsageExtension(object):
    def test_no_key_usage(self, backend):
        cert = _load_cert(
            os.path.join("x509", "verisign_md2_root.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions
        with pytest.raises(x509.ExtensionNotFound) as exc:
            ext.get_extension_for_oid(ExtensionOID.KEY_USAGE)

        assert exc.value.oid == ExtensionOID.KEY_USAGE

    def test_all_purposes(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "all_key_usages.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        extensions = cert.extensions
        ext = extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        assert ext is not None

        ku = ext.value
        assert ku.digital_signature is True
        assert ku.content_commitment is True
        assert ku.key_encipherment is True
        assert ku.data_encipherment is True
        assert ku.key_agreement is True
        assert ku.key_cert_sign is True
        assert ku.crl_sign is True
        assert ku.encipher_only is True
        assert ku.decipher_only is True

    def test_key_cert_sign_crl_sign(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs", "pathLenConstraint6CACert.crt"
            ),
            x509.load_der_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        assert ext is not None
        assert ext.critical is True

        ku = ext.value
        assert ku.digital_signature is False
        assert ku.content_commitment is False
        assert ku.key_encipherment is False
        assert ku.data_encipherment is False
        assert ku.key_agreement is False
        assert ku.key_cert_sign is True
        assert ku.crl_sign is True


class TestDNSName(object):
    def test_non_a_label(self):
        with pytest.raises(ValueError):
            x509.DNSName(".\xf5\xe4\xf6\xfc.example.com")

    def test_init(self):
        name = x509.DNSName("*.xn--4ca7aey.example.com")
        assert name.value == "*.xn--4ca7aey.example.com"

        with pytest.raises(TypeError):
            x509.DNSName(1.3)  # type:ignore[arg-type]

        with pytest.raises(TypeError):
            x509.DNSName(b"bytes not allowed")  # type:ignore[arg-type]

    def test_ne(self):
        n1 = x509.DNSName("test1")
        n2 = x509.DNSName("test2")
        n3 = x509.DNSName("test2")
        assert n1 != n2
        assert not (n2 != n3)

    def test_hash(self):
        n1 = x509.DNSName("test1")
        n2 = x509.DNSName("test2")
        n3 = x509.DNSName("test2")
        assert hash(n1) != hash(n2)
        assert hash(n2) == hash(n3)


class TestDirectoryName(object):
    def test_not_name(self):
        with pytest.raises(TypeError):
            x509.DirectoryName(b"notaname")  # type:ignore[arg-type]

        with pytest.raises(TypeError):
            x509.DirectoryName(1.3)  # type:ignore[arg-type]

    def test_repr(self):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "value1")])
        gn = x509.DirectoryName(name)
        assert repr(gn) == "<DirectoryName(value=<Name(CN=value1)>)>"

    def test_eq(self):
        name = x509.Name(
            [x509.NameAttribute(x509.ObjectIdentifier("2.999.1"), "value1")]
        )
        name2 = x509.Name(
            [x509.NameAttribute(x509.ObjectIdentifier("2.999.1"), "value1")]
        )
        gn = x509.DirectoryName(name)
        gn2 = x509.DirectoryName(name2)
        assert gn == gn2

    def test_ne(self):
        name = x509.Name(
            [x509.NameAttribute(x509.ObjectIdentifier("2.999.1"), "value1")]
        )
        name2 = x509.Name(
            [x509.NameAttribute(x509.ObjectIdentifier("2.999.2"), "value2")]
        )
        gn = x509.DirectoryName(name)
        gn2 = x509.DirectoryName(name2)
        assert gn != gn2
        assert gn != object()

    def test_hash(self):
        name = x509.Name(
            [x509.NameAttribute(x509.ObjectIdentifier("2.999.1"), "value1")]
        )
        name2 = x509.Name(
            [x509.NameAttribute(x509.ObjectIdentifier("2.999.2"), "value2")]
        )
        gn = x509.DirectoryName(name)
        gn2 = x509.DirectoryName(name)
        gn3 = x509.DirectoryName(name2)
        assert hash(gn) == hash(gn2)
        assert hash(gn) != hash(gn3)


class TestRFC822Name(object):
    def test_repr(self):
        gn = x509.RFC822Name("string")
        assert repr(gn) == "<RFC822Name(value='string')>"

    def test_equality(self):
        gn = x509.RFC822Name("string")
        gn2 = x509.RFC822Name("string2")
        gn3 = x509.RFC822Name("string")
        assert gn != gn2
        assert gn != object()
        assert gn == gn3

    def test_not_text(self):
        with pytest.raises(TypeError):
            x509.RFC822Name(1.3)  # type:ignore[arg-type]

        with pytest.raises(TypeError):
            x509.RFC822Name(b"bytes")  # type:ignore[arg-type]

    def test_invalid_email(self):
        with pytest.raises(ValueError):
            x509.RFC822Name("Name <email>")

        with pytest.raises(ValueError):
            x509.RFC822Name("")

    def test_single_label(self):
        gn = x509.RFC822Name("administrator")
        assert gn.value == "administrator"

    def test_non_a_label(self):
        with pytest.raises(ValueError):
            x509.RFC822Name("email@em\xe5\xefl.com")

    def test_hash(self):
        g1 = x509.RFC822Name("email@host.com")
        g2 = x509.RFC822Name("email@host.com")
        g3 = x509.RFC822Name("admin@host.com")

        assert hash(g1) == hash(g2)
        assert hash(g1) != hash(g3)


class TestUniformResourceIdentifier(object):
    def test_equality(self):
        gn = x509.UniformResourceIdentifier("string")
        gn2 = x509.UniformResourceIdentifier("string2")
        gn3 = x509.UniformResourceIdentifier("string")
        assert gn != gn2
        assert gn != object()
        assert gn == gn3

    def test_not_text(self):
        with pytest.raises(TypeError):
            x509.UniformResourceIdentifier(1.3)  # type:ignore[arg-type]

    def test_no_parsed_hostname(self):
        gn = x509.UniformResourceIdentifier("singlelabel")
        assert gn.value == "singlelabel"

    def test_with_port(self):
        gn = x509.UniformResourceIdentifier("singlelabel:443/test")
        assert gn.value == "singlelabel:443/test"

    def test_non_a_label(self):
        with pytest.raises(ValueError):
            x509.UniformResourceIdentifier(
                "http://\u043f\u044b\u043a\u0430.cryptography"
            )

    def test_empty_hostname(self):
        gn = x509.UniformResourceIdentifier("ldap:///some-nonsense")
        assert gn.value == "ldap:///some-nonsense"

    def test_hash(self):
        g1 = x509.UniformResourceIdentifier("http://host.com")
        g2 = x509.UniformResourceIdentifier("http://host.com")
        g3 = x509.UniformResourceIdentifier("http://other.com")

        assert hash(g1) == hash(g2)
        assert hash(g1) != hash(g3)

    def test_repr(self):
        gn = x509.UniformResourceIdentifier("string")
        assert repr(gn) == ("<UniformResourceIdentifier(value='string')>")


class TestRegisteredID(object):
    def test_not_oid(self):
        with pytest.raises(TypeError):
            x509.RegisteredID(b"notanoid")  # type:ignore[arg-type]

        with pytest.raises(TypeError):
            x509.RegisteredID(1.3)  # type:ignore[arg-type]

    def test_repr(self):
        gn = x509.RegisteredID(NameOID.COMMON_NAME)
        assert repr(gn) == (
            "<RegisteredID(value=<ObjectIdentifier(oid=2.5.4.3, name=commonNam"
            "e)>)>"
        )

    def test_eq(self):
        gn = x509.RegisteredID(NameOID.COMMON_NAME)
        gn2 = x509.RegisteredID(NameOID.COMMON_NAME)
        assert gn == gn2

    def test_ne(self):
        gn = x509.RegisteredID(NameOID.COMMON_NAME)
        gn2 = x509.RegisteredID(ExtensionOID.BASIC_CONSTRAINTS)
        assert gn != gn2
        assert gn != object()

    def test_hash(self):
        gn = x509.RegisteredID(NameOID.COMMON_NAME)
        gn2 = x509.RegisteredID(NameOID.COMMON_NAME)
        gn3 = x509.RegisteredID(ExtensionOID.BASIC_CONSTRAINTS)
        assert hash(gn) == hash(gn2)
        assert hash(gn) != hash(gn3)


class TestIPAddress(object):
    def test_not_ipaddress(self):
        with pytest.raises(TypeError):
            x509.IPAddress(b"notanipaddress")  # type:ignore[arg-type]

        with pytest.raises(TypeError):
            x509.IPAddress(1.3)  # type:ignore[arg-type]

    def test_repr(self):
        gn = x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
        assert repr(gn) == "<IPAddress(value=127.0.0.1)>"

        gn2 = x509.IPAddress(ipaddress.IPv6Address("ff::"))
        assert repr(gn2) == "<IPAddress(value=ff::)>"

        gn3 = x509.IPAddress(ipaddress.IPv4Network("192.168.0.0/24"))
        assert repr(gn3) == "<IPAddress(value=192.168.0.0/24)>"

        gn4 = x509.IPAddress(ipaddress.IPv6Network("ff::/96"))
        assert repr(gn4) == "<IPAddress(value=ff::/96)>"

    def test_eq(self):
        gn = x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
        gn2 = x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
        assert gn == gn2

    def test_ne(self):
        gn = x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
        gn2 = x509.IPAddress(ipaddress.IPv4Address("127.0.0.2"))
        assert gn != gn2
        assert gn != object()

    def test_hash(self):
        gn = x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
        gn2 = x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
        gn3 = x509.IPAddress(ipaddress.IPv4Address("127.0.0.2"))
        assert hash(gn) == hash(gn2)
        assert hash(gn) != hash(gn3)


class TestOtherName(object):
    def test_invalid_args(self):
        with pytest.raises(TypeError):
            x509.OtherName(
                b"notanobjectidentifier",  # type:ignore[arg-type]
                b"derdata",
            )

        with pytest.raises(TypeError):
            x509.OtherName(
                x509.ObjectIdentifier("1.2.3.4"),
                "notderdata",  # type:ignore[arg-type]
            )

    def test_repr(self):
        gn = x509.OtherName(x509.ObjectIdentifier("1.2.3.4"), b"derdata")
        assert repr(gn) == (
            "<OtherName(type_id=<ObjectIdentifier(oid=1.2.3.4, "
            "name=Unknown OID)>, value=b'derdata')>"
        )

        gn = x509.OtherName(x509.ObjectIdentifier("2.5.4.65"), b"derdata")
        assert repr(gn) == (
            "<OtherName(type_id=<ObjectIdentifier(oid=2.5.4.65, "
            "name=pseudonym)>, value=b'derdata')>"
        )

    def test_eq(self):
        gn = x509.OtherName(x509.ObjectIdentifier("1.2.3.4"), b"derdata")
        gn2 = x509.OtherName(x509.ObjectIdentifier("1.2.3.4"), b"derdata")
        assert gn == gn2

    def test_ne(self):
        gn = x509.OtherName(x509.ObjectIdentifier("1.2.3.4"), b"derdata")
        assert gn != object()

        gn2 = x509.OtherName(x509.ObjectIdentifier("1.2.3.4"), b"derdata2")
        assert gn != gn2

        gn2 = x509.OtherName(x509.ObjectIdentifier("1.2.3.5"), b"derdata")
        assert gn != gn2

    def test_hash(self):
        gn = x509.OtherName(x509.ObjectIdentifier("1.2.3.4"), b"derdata")
        gn2 = x509.OtherName(x509.ObjectIdentifier("1.2.3.4"), b"derdata")
        gn3 = x509.OtherName(x509.ObjectIdentifier("1.2.3.5"), b"derdata")
        assert hash(gn) == hash(gn2)
        assert hash(gn) != hash(gn3)


class TestGeneralNames(object):
    def test_get_values_for_type(self):
        gns = x509.GeneralNames([x509.DNSName("cryptography.io")])
        names = gns.get_values_for_type(x509.DNSName)
        assert names == ["cryptography.io"]

    def test_iter_names(self):
        gns = x509.GeneralNames(
            [x509.DNSName("cryptography.io"), x509.DNSName("crypto.local")]
        )
        assert len(gns) == 2
        assert list(gns) == [
            x509.DNSName("cryptography.io"),
            x509.DNSName("crypto.local"),
        ]

    def test_iter_input(self):
        names = [
            x509.DNSName("cryptography.io"),
            x509.DNSName("crypto.local"),
        ]
        gns = x509.GeneralNames(iter(names))
        assert list(gns) == names

    def test_indexing(self):
        gn = x509.GeneralNames(
            [
                x509.DNSName("cryptography.io"),
                x509.DNSName("crypto.local"),
                x509.DNSName("another.local"),
                x509.RFC822Name("email@another.local"),
                x509.UniformResourceIdentifier("http://another.local"),
            ]
        )
        assert gn[-1] == gn[4]
        assert gn[2:6:2] == [gn[2], gn[4]]

    def test_invalid_general_names(self):
        with pytest.raises(TypeError):
            x509.GeneralNames(
                [
                    x509.DNSName("cryptography.io"),
                    "invalid",  # type:ignore[list-item]
                ]
            )

    def test_repr(self):
        gns = x509.GeneralNames([x509.DNSName("cryptography.io")])
        assert repr(gns) == (
            "<GeneralNames([<DNSName(value='cryptography.io')>])>"
        )

    def test_eq(self):
        gns = x509.GeneralNames([x509.DNSName("cryptography.io")])
        gns2 = x509.GeneralNames([x509.DNSName("cryptography.io")])
        assert gns == gns2

    def test_ne(self):
        gns = x509.GeneralNames([x509.DNSName("cryptography.io")])
        gns2 = x509.GeneralNames([x509.RFC822Name("admin@cryptography.io")])
        assert gns != gns2
        assert gns != object()

    def test_hash(self):
        gns = x509.GeneralNames([x509.DNSName("cryptography.io")])
        gns2 = x509.GeneralNames([x509.DNSName("cryptography.io")])
        gns3 = x509.GeneralNames([x509.RFC822Name("admin@cryptography.io")])
        assert hash(gns) == hash(gns2)
        assert hash(gns) != hash(gns3)


class TestIssuerAlternativeName(object):
    def test_get_values_for_type(self):
        san = x509.IssuerAlternativeName([x509.DNSName("cryptography.io")])
        names = san.get_values_for_type(x509.DNSName)
        assert names == ["cryptography.io"]

    def test_iter_names(self):
        san = x509.IssuerAlternativeName(
            [x509.DNSName("cryptography.io"), x509.DNSName("crypto.local")]
        )
        assert len(san) == 2
        assert list(san) == [
            x509.DNSName("cryptography.io"),
            x509.DNSName("crypto.local"),
        ]

    def test_indexing(self):
        ian = x509.IssuerAlternativeName(
            [
                x509.DNSName("cryptography.io"),
                x509.DNSName("crypto.local"),
                x509.DNSName("another.local"),
                x509.RFC822Name("email@another.local"),
                x509.UniformResourceIdentifier("http://another.local"),
            ]
        )
        assert ian[-1] == ian[4]
        assert ian[2:6:2] == [ian[2], ian[4]]

    def test_invalid_general_names(self):
        with pytest.raises(TypeError):
            x509.IssuerAlternativeName(
                [
                    x509.DNSName("cryptography.io"),
                    "invalid",  # type:ignore[list-item]
                ]
            )

    def test_repr(self):
        san = x509.IssuerAlternativeName([x509.DNSName("cryptography.io")])
        assert repr(san) == (
            "<IssuerAlternativeName("
            "<GeneralNames([<DNSName(value='cryptography.io')>])>)>"
        )

    def test_eq(self):
        san = x509.IssuerAlternativeName([x509.DNSName("cryptography.io")])
        san2 = x509.IssuerAlternativeName([x509.DNSName("cryptography.io")])
        assert san == san2

    def test_ne(self):
        san = x509.IssuerAlternativeName([x509.DNSName("cryptography.io")])
        san2 = x509.IssuerAlternativeName(
            [x509.RFC822Name("admin@cryptography.io")]
        )
        assert san != san2
        assert san != object()

    def test_hash(self):
        ian = x509.IssuerAlternativeName([x509.DNSName("cryptography.io")])
        ian2 = x509.IssuerAlternativeName([x509.DNSName("cryptography.io")])
        ian3 = x509.IssuerAlternativeName(
            [x509.RFC822Name("admin@cryptography.io")]
        )
        assert hash(ian) == hash(ian2)
        assert hash(ian) != hash(ian3)


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestRSAIssuerAlternativeNameExtension(object):
    def test_uri(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "ian_uri.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.ISSUER_ALTERNATIVE_NAME
        )
        assert list(ext.value) == [
            x509.UniformResourceIdentifier("http://path.to.root/root.crt"),
        ]


class TestCRLNumber(object):
    def test_eq(self):
        crl_number = x509.CRLNumber(15)
        assert crl_number == x509.CRLNumber(15)

    def test_ne(self):
        crl_number = x509.CRLNumber(15)
        assert crl_number != x509.CRLNumber(14)
        assert crl_number != object()

    def test_repr(self):
        crl_number = x509.CRLNumber(15)
        assert repr(crl_number) == "<CRLNumber(15)>"

    def test_invalid_number(self):
        with pytest.raises(TypeError):
            x509.CRLNumber("notanumber")  # type:ignore[arg-type]

    def test_hash(self):
        c1 = x509.CRLNumber(1)
        c2 = x509.CRLNumber(1)
        c3 = x509.CRLNumber(2)
        assert hash(c1) == hash(c2)
        assert hash(c1) != hash(c3)


class TestSubjectAlternativeName(object):
    def test_get_values_for_type(self):
        san = x509.SubjectAlternativeName([x509.DNSName("cryptography.io")])
        names = san.get_values_for_type(x509.DNSName)
        assert names == ["cryptography.io"]

    def test_iter_names(self):
        san = x509.SubjectAlternativeName(
            [x509.DNSName("cryptography.io"), x509.DNSName("crypto.local")]
        )
        assert len(san) == 2
        assert list(san) == [
            x509.DNSName("cryptography.io"),
            x509.DNSName("crypto.local"),
        ]

    def test_indexing(self):
        san = x509.SubjectAlternativeName(
            [
                x509.DNSName("cryptography.io"),
                x509.DNSName("crypto.local"),
                x509.DNSName("another.local"),
                x509.RFC822Name("email@another.local"),
                x509.UniformResourceIdentifier("http://another.local"),
            ]
        )
        assert san[-1] == san[4]
        assert san[2:6:2] == [san[2], san[4]]

    def test_invalid_general_names(self):
        with pytest.raises(TypeError):
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("cryptography.io"),
                    "invalid",  # type:ignore[list-item]
                ]
            )

    def test_repr(self):
        san = x509.SubjectAlternativeName([x509.DNSName("cryptography.io")])
        assert repr(san) == (
            "<SubjectAlternativeName("
            "<GeneralNames([<DNSName(value='cryptography.io')>])>)>"
        )

    def test_eq(self):
        san = x509.SubjectAlternativeName([x509.DNSName("cryptography.io")])
        san2 = x509.SubjectAlternativeName([x509.DNSName("cryptography.io")])
        assert san == san2

    def test_ne(self):
        san = x509.SubjectAlternativeName([x509.DNSName("cryptography.io")])
        san2 = x509.SubjectAlternativeName(
            [x509.RFC822Name("admin@cryptography.io")]
        )
        assert san != san2
        assert san != object()

    def test_hash(self):
        san = x509.SubjectAlternativeName([x509.DNSName("cryptography.io")])
        san2 = x509.SubjectAlternativeName([x509.DNSName("cryptography.io")])
        san3 = x509.SubjectAlternativeName(
            [x509.RFC822Name("admin@cryptography.io")]
        )
        assert hash(san) == hash(san2)
        assert hash(san) != hash(san3)


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestRSASubjectAlternativeNameExtension(object):
    def test_dns_name(self, backend):
        cert = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert ext is not None
        assert ext.critical is False

        san = ext.value

        dns = san.get_values_for_type(x509.DNSName)
        assert dns == ["www.cryptography.io", "cryptography.io"]

    def test_wildcard_dns_name(self, backend):
        cert = _load_cert(
            os.path.join("x509", "wildcard_san.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )

        dns = ext.value.get_values_for_type(x509.DNSName)
        assert dns == [
            "*.langui.sh",
            "langui.sh",
            "*.saseliminator.com",
            "saseliminator.com",
        ]

    def test_san_empty_hostname(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "san_empty_hostname.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )

        dns = san.value.get_values_for_type(x509.DNSName)
        assert dns == [""]

    def test_san_wildcard_idna_dns_name(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "san_wildcard_idna.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )

        dns = ext.value.get_values_for_type(x509.DNSName)
        assert dns == ["*.xn--80ato2c.cryptography"]

    def test_unsupported_gn(self, backend):
        cert = _load_cert(
            os.path.join("x509", "san_x400address.der"),
            x509.load_der_x509_certificate,
            backend,
        )
        with pytest.raises(x509.UnsupportedGeneralNameType) as exc:
            cert.extensions

        assert exc.value.type == 3

    def test_registered_id(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "san_registered_id.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert ext is not None
        assert ext.critical is False

        san = ext.value
        rid = san.get_values_for_type(x509.RegisteredID)
        assert rid == [x509.ObjectIdentifier("1.2.3.4")]

    def test_uri(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "san_uri_with_port.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert ext is not None
        uri = ext.value.get_values_for_type(x509.UniformResourceIdentifier)
        assert uri == [
            "gopher://xn--80ato2c.cryptography:70/path?q=s#hel" "lo",
            "http://someregulardomain.com",
        ]

    def test_ipaddress(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "san_ipaddr.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert ext is not None
        assert ext.critical is False

        san = ext.value

        ip = san.get_values_for_type(x509.IPAddress)
        assert [
            ipaddress.ip_address("127.0.0.1"),
            ipaddress.ip_address("ff::"),
        ] == ip

    def test_dirname(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "san_dirname.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert ext is not None
        assert ext.critical is False

        san = ext.value

        dirname = san.get_values_for_type(x509.DirectoryName)
        assert [
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "test"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org"),
                    x509.NameAttribute(
                        NameOID.STATE_OR_PROVINCE_NAME, "Texas"
                    ),
                ]
            )
        ] == dirname

    def test_rfc822name(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "san_rfc822_idna.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert ext is not None
        assert ext.critical is False

        san = ext.value

        rfc822name = san.get_values_for_type(x509.RFC822Name)
        assert ["email@xn--eml-vla4c.com"] == rfc822name

    def test_idna2003_invalid(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "san_idna2003_dnsname.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value

        assert len(san) == 1
        [name] = san
        assert name.value == "xn--k4h.ws"

    def test_unicode_rfc822_name_dns_name_uri(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "san_idna_names.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert ext is not None
        rfc822_name = ext.value.get_values_for_type(x509.RFC822Name)
        dns_name = ext.value.get_values_for_type(x509.DNSName)
        uri = ext.value.get_values_for_type(x509.UniformResourceIdentifier)
        assert rfc822_name == ["email@xn--80ato2c.cryptography"]
        assert dns_name == ["xn--80ato2c.cryptography"]
        assert uri == ["https://www.xn--80ato2c.cryptography"]

    def test_rfc822name_dnsname_ipaddress_directoryname_uri(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "san_email_dns_ip_dirname_uri.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert ext is not None
        assert ext.critical is False

        san = ext.value

        rfc822_name = san.get_values_for_type(x509.RFC822Name)
        uri = san.get_values_for_type(x509.UniformResourceIdentifier)
        dns = san.get_values_for_type(x509.DNSName)
        ip = san.get_values_for_type(x509.IPAddress)
        dirname = san.get_values_for_type(x509.DirectoryName)
        assert ["user@cryptography.io"] == rfc822_name
        assert ["https://cryptography.io"] == uri
        assert ["cryptography.io"] == dns
        assert [
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "dirCN"),
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME, "Cryptographic Authority"
                    ),
                ]
            )
        ] == dirname
        assert [
            ipaddress.ip_address("127.0.0.1"),
            ipaddress.ip_address("ff::"),
        ] == ip

    def test_invalid_rfc822name(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "san_rfc822_names.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        values = san.get_values_for_type(x509.RFC822Name)
        assert values == [
            "email",
            "email <email>",
            "email <email@email>",
            "email <email@xn--eml-vla4c.com>",
            "myemail:",
        ]

    def test_other_name(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "san_other_name.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert ext is not None
        assert ext.critical is False

        expected = x509.OtherName(
            x509.ObjectIdentifier("1.2.3.4"), b"\x16\x0bHello World"
        )
        assert len(ext.value) == 1
        assert list(ext.value)[0] == expected

        othernames = ext.value.get_values_for_type(x509.OtherName)
        assert othernames == [expected]

    def test_certbuilder(self, backend):
        sans = [
            "*.example.org",
            "*.xn--4ca7aey.example.com",
            "foobar.example.net",
        ]
        private_key = RSA_KEY_2048.private_key(backend)
        builder = _make_certbuilder(private_key)
        builder = builder.add_extension(
            SubjectAlternativeName(list(map(DNSName, sans))), True
        )

        cert = builder.sign(private_key, hashes.SHA1(), backend)
        result = [
            x.value
            for x in cert.extensions.get_extension_for_class(
                SubjectAlternativeName
            ).value
        ]
        assert result == sans


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestExtendedKeyUsageExtension(object):
    def test_eku(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "extended_key_usage.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )
        assert ext is not None
        assert ext.critical is False

        assert [
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1"),
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2"),
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.3"),
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.4"),
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.9"),
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.8"),
            x509.ObjectIdentifier("2.5.29.37.0"),
            x509.ObjectIdentifier("2.16.840.1.113730.4.1"),
        ] == list(ext.value)


class TestAccessDescription(object):
    def test_invalid_access_method(self):
        with pytest.raises(TypeError):
            x509.AccessDescription(
                "notanoid", x509.DNSName("test")  # type:ignore[arg-type]
            )

    def test_invalid_access_location(self):
        with pytest.raises(TypeError):
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                "invalid",  # type:ignore[arg-type]
            )

    def test_valid_nonstandard_method(self):
        ad = x509.AccessDescription(
            ObjectIdentifier("2.999.1"),
            x509.UniformResourceIdentifier("http://example.com"),
        )
        assert ad is not None

    def test_repr(self):
        ad = x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier("http://ocsp.domain.com"),
        )
        assert repr(ad) == (
            "<AccessDescription(access_method=<ObjectIdentifier(oid=1.3.6"
            ".1.5.5.7.48.1, name=OCSP)>, access_location=<UniformResource"
            "Identifier(value='http://ocsp.domain.com')>)>"
        )

    def test_eq(self):
        ad = x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier("http://ocsp.domain.com"),
        )
        ad2 = x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier("http://ocsp.domain.com"),
        )
        assert ad == ad2

    def test_ne(self):
        ad = x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier("http://ocsp.domain.com"),
        )
        ad2 = x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier("http://ocsp.domain.com"),
        )
        ad3 = x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier("http://notthesame"),
        )
        assert ad != ad2
        assert ad != ad3
        assert ad != object()

    def test_hash(self):
        ad = x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier("http://ocsp.domain.com"),
        )
        ad2 = x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier("http://ocsp.domain.com"),
        )
        ad3 = x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier("http://ocsp.domain.com"),
        )
        assert hash(ad) == hash(ad2)
        assert hash(ad) != hash(ad3)


class TestPolicyConstraints(object):
    def test_invalid_explicit_policy(self):
        with pytest.raises(TypeError):
            x509.PolicyConstraints("invalid", None)  # type:ignore[arg-type]

    def test_invalid_inhibit_policy(self):
        with pytest.raises(TypeError):
            x509.PolicyConstraints(None, "invalid")  # type:ignore[arg-type]

    def test_both_none(self):
        with pytest.raises(ValueError):
            x509.PolicyConstraints(None, None)

    def test_repr(self):
        pc = x509.PolicyConstraints(0, None)

        assert repr(pc) == (
            "<PolicyConstraints(require_explicit_policy=0, inhibit_policy_ma"
            "pping=None)>"
        )

    def test_eq(self):
        pc = x509.PolicyConstraints(2, 1)
        pc2 = x509.PolicyConstraints(2, 1)
        assert pc == pc2

    def test_ne(self):
        pc = x509.PolicyConstraints(2, 1)
        pc2 = x509.PolicyConstraints(2, 2)
        pc3 = x509.PolicyConstraints(3, 1)
        assert pc != pc2
        assert pc != pc3
        assert pc != object()

    def test_hash(self):
        pc = x509.PolicyConstraints(2, 1)
        pc2 = x509.PolicyConstraints(2, 1)
        pc3 = x509.PolicyConstraints(2, None)
        assert hash(pc) == hash(pc2)
        assert hash(pc) != hash(pc3)


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestPolicyConstraintsExtension(object):
    def test_inhibit_policy_mapping(self, backend):
        cert = _load_cert(
            os.path.join("x509", "department-of-state-root.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.POLICY_CONSTRAINTS,
        )
        assert ext.critical is True

        assert ext.value == x509.PolicyConstraints(
            require_explicit_policy=None,
            inhibit_policy_mapping=0,
        )

    def test_require_explicit_policy(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "policy_constraints_explicit.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.POLICY_CONSTRAINTS
        )
        assert ext.critical is True
        assert ext.value == x509.PolicyConstraints(
            require_explicit_policy=1,
            inhibit_policy_mapping=None,
        )


class TestAuthorityInformationAccess(object):
    def test_invalid_descriptions(self):
        with pytest.raises(TypeError):
            x509.AuthorityInformationAccess(
                ["notanAccessDescription"]  # type:ignore[list-item]
            )

    def test_iter_len(self):
        aia = x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.domain.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://domain.com/ca.crt"),
                ),
            ]
        )
        assert len(aia) == 2
        assert list(aia) == [
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier("http://ocsp.domain.com"),
            ),
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier("http://domain.com/ca.crt"),
            ),
        ]

    def test_iter_input(self):
        desc = [
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier("http://ocsp.domain.com"),
            )
        ]
        aia = x509.AuthorityInformationAccess(iter(desc))
        assert list(aia) == desc

    def test_repr(self):
        aia = x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.domain.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://domain.com/ca.crt"),
                ),
            ]
        )
        assert repr(aia) == (
            "<AuthorityInformationAccess([<AccessDescription(access_method"
            "=<ObjectIdentifier(oid=1.3.6.1.5.5.7.48.1, name=OCSP)>, acces"
            "s_location=<UniformResourceIdentifier(value='http://oc"
            "sp.domain.com')>)>, <AccessDescription(access_method=<ObjectI"
            "dentifier(oid=1.3.6.1.5.5.7.48.2, name=caIssuers)>, access_lo"
            "cation=<UniformResourceIdentifier(value='http://domain"
            ".com/ca.crt')>)>])>"
        )

    def test_eq(self):
        aia = x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.domain.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://domain.com/ca.crt"),
                ),
            ]
        )
        aia2 = x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.domain.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://domain.com/ca.crt"),
                ),
            ]
        )
        assert aia == aia2

    def test_ne(self):
        aia = x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.domain.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://domain.com/ca.crt"),
                ),
            ]
        )
        aia2 = x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.domain.com"),
                ),
            ]
        )

        assert aia != aia2
        assert aia != object()

    def test_indexing(self):
        aia = x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.domain.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://domain.com/ca.crt"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp2.domain.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp3.domain.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp4.domain.com"),
                ),
            ]
        )
        assert aia[-1] == aia[4]
        assert aia[2:6:2] == [aia[2], aia[4]]

    def test_hash(self):
        aia = x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.domain.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://domain.com/ca.crt"),
                ),
            ]
        )
        aia2 = x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.domain.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://domain.com/ca.crt"),
                ),
            ]
        )
        aia3 = x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.other.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://domain.com/ca.crt"),
                ),
            ]
        )
        assert hash(aia) == hash(aia2)
        assert hash(aia) != hash(aia3)


class TestSubjectInformationAccess(object):
    def test_invalid_descriptions(self):
        with pytest.raises(TypeError):
            x509.SubjectInformationAccess(
                ["notanAccessDescription"]  # type:ignore[list-item]
            )

    def test_iter_len(self):
        sia = x509.SubjectInformationAccess(
            [
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca.domain.com"),
                ),
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca2.domain.com"),
                ),
            ]
        )
        assert len(sia) == 2
        assert list(sia) == [
            x509.AccessDescription(
                SubjectInformationAccessOID.CA_REPOSITORY,
                x509.UniformResourceIdentifier("http://ca.domain.com"),
            ),
            x509.AccessDescription(
                SubjectInformationAccessOID.CA_REPOSITORY,
                x509.UniformResourceIdentifier("http://ca2.domain.com"),
            ),
        ]

    def test_iter_input(self):
        desc = [
            x509.AccessDescription(
                SubjectInformationAccessOID.CA_REPOSITORY,
                x509.UniformResourceIdentifier("http://ca.domain.com"),
            )
        ]
        sia = x509.SubjectInformationAccess(iter(desc))
        assert list(sia) == desc

    def test_repr(self):
        sia = x509.SubjectInformationAccess(
            [
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca.domain.com"),
                )
            ]
        )
        assert repr(sia) == (
            "<SubjectInformationAccess([<AccessDescription(access_method"
            "=<ObjectIdentifier(oid=1.3.6.1.5.5.7.48.5, name=caRepositor"
            "y)>, access_location=<UniformResourceIdentifier(value='http"
            "://ca.domain.com')>)>])>"
        )

    def test_eq(self):
        sia = x509.SubjectInformationAccess(
            [
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca.domain.com"),
                ),
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca2.domain.com"),
                ),
            ]
        )
        sia2 = x509.SubjectInformationAccess(
            [
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca.domain.com"),
                ),
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca2.domain.com"),
                ),
            ]
        )
        assert sia == sia2

    def test_ne(self):
        sia = x509.SubjectInformationAccess(
            [
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca.domain.com"),
                ),
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca2.domain.com"),
                ),
            ]
        )
        sia2 = x509.SubjectInformationAccess(
            [
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca.domain.com"),
                ),
            ]
        )

        assert sia != sia2
        assert sia != object()

    def test_indexing(self):
        sia = x509.SubjectInformationAccess(
            [
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca.domain.com"),
                ),
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca2.domain.com"),
                ),
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca3.domain.com"),
                ),
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca4.domain.com"),
                ),
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca5.domain.com"),
                ),
            ]
        )
        assert sia[-1] == sia[4]
        assert sia[2:6:2] == [sia[2], sia[4]]

    def test_hash(self):
        sia = x509.SubjectInformationAccess(
            [
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca.domain.com"),
                ),
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca2.domain.com"),
                ),
            ]
        )
        sia2 = x509.SubjectInformationAccess(
            [
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca.domain.com"),
                ),
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca2.domain.com"),
                ),
            ]
        )
        sia3 = x509.SubjectInformationAccess(
            [
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca.domain.com"),
                ),
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("http://ca3.domain.com"),
                ),
            ]
        )
        assert hash(sia) == hash(sia2)
        assert hash(sia) != hash(sia3)


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestSubjectInformationAccessExtension(object):
    def test_sia(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "sia.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_INFORMATION_ACCESS
        )
        assert ext is not None
        assert ext.critical is False

        assert ext.value == x509.SubjectInformationAccess(
            [
                x509.AccessDescription(
                    SubjectInformationAccessOID.CA_REPOSITORY,
                    x509.UniformResourceIdentifier("https://my.ca.issuer/"),
                ),
                x509.AccessDescription(
                    x509.ObjectIdentifier("2.999.7"),
                    x509.UniformResourceIdentifier(
                        "gopher://info-mac-archive"
                    ),
                ),
            ]
        )


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestAuthorityInformationAccessExtension(object):
    def test_aia_ocsp_ca_issuers(self, backend):
        cert = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        assert ext is not None
        assert ext.critical is False

        assert ext.value == x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://gv.symcd.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier(
                        "http://gv.symcb.com/gv.crt"
                    ),
                ),
            ]
        )

    def test_aia_multiple_ocsp_ca_issuers(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "aia_ocsp_ca_issuers.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        assert ext is not None
        assert ext.critical is False

        assert ext.value == x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.domain.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp2.domain.com"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.DirectoryName(
                        x509.Name(
                            [
                                x509.NameAttribute(
                                    NameOID.COMMON_NAME, "myCN"
                                ),
                                x509.NameAttribute(
                                    NameOID.ORGANIZATION_NAME, "some Org"
                                ),
                            ]
                        )
                    ),
                ),
            ]
        )

    def test_aia_ocsp_only(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "aia_ocsp.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        assert ext is not None
        assert ext.critical is False

        assert ext.value == x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.domain.com"),
                ),
            ]
        )

    def test_aia_ca_issuers_only(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "aia_ca_issuers.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        assert ext is not None
        assert ext.critical is False

        assert ext.value == x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.DirectoryName(
                        x509.Name(
                            [
                                x509.NameAttribute(
                                    NameOID.COMMON_NAME, "myCN"
                                ),
                                x509.NameAttribute(
                                    NameOID.ORGANIZATION_NAME, "some Org"
                                ),
                            ]
                        )
                    ),
                ),
            ]
        )


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestAuthorityKeyIdentifierExtension(object):
    def test_aki_keyid(self, backend):
        cert = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        assert ext is not None
        assert ext.critical is False

        assert ext.value.key_identifier == (
            b"\xc3\x9c\xf3\xfc\xd3F\x084\xbb\xceF\x7f\xa0|[\xf3\xe2\x08\xcbY"
        )
        assert ext.value.authority_cert_issuer is None
        assert ext.value.authority_cert_serial_number is None

    def test_aki_all_fields(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "authority_key_identifier.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        assert ext is not None
        assert ext.critical is False

        assert ext.value.key_identifier == (
            b"9E>\xca=b\x1d\xea\x86I\xf6Z\xab@\xb7\xa4p\x98\xf1\xec"
        )
        assert ext.value.authority_cert_issuer == [
            x509.DirectoryName(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyCA"),
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io"
                        ),
                    ]
                )
            )
        ]
        assert ext.value.authority_cert_serial_number == 3

    def test_aki_no_keyid(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom", "authority_key_identifier_no_keyid.pem"
            ),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        assert ext is not None
        assert ext.critical is False

        assert ext.value.key_identifier is None
        assert ext.value.authority_cert_issuer == [
            x509.DirectoryName(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyCA"),
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io"
                        ),
                    ]
                )
            )
        ]
        assert ext.value.authority_cert_serial_number == 3

    def test_from_certificate(self, backend):
        issuer_cert = _load_cert(
            os.path.join("x509", "rapidssl_sha256_ca_g3.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        cert = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_cert.public_key()
        )
        assert ext.value == aki

    def test_from_issuer_subject_key_identifier(self, backend):
        issuer_cert = _load_cert(
            os.path.join("x509", "rapidssl_sha256_ca_g3.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        cert = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        ski_ext = issuer_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ski_ext.value
        )
        assert ext.value == aki


class TestNameConstraints(object):
    def test_ipaddress_wrong_type(self):
        with pytest.raises(TypeError):
            x509.NameConstraints(
                permitted_subtrees=[
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
                ],
                excluded_subtrees=None,
            )

        with pytest.raises(TypeError):
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
                ],
            )

    def test_ipaddress_allowed_type(self):
        permitted = [x509.IPAddress(ipaddress.IPv4Network("192.168.0.0/29"))]
        excluded = [x509.IPAddress(ipaddress.IPv4Network("10.10.0.0/24"))]
        nc = x509.NameConstraints(
            permitted_subtrees=permitted, excluded_subtrees=excluded
        )
        assert nc.permitted_subtrees == permitted
        assert nc.excluded_subtrees == excluded

    def test_invalid_permitted_subtrees(self):
        with pytest.raises(TypeError):
            x509.NameConstraints("badpermitted", None)  # type:ignore[arg-type]

    def test_invalid_excluded_subtrees(self):
        with pytest.raises(TypeError):
            x509.NameConstraints(None, "badexcluded")  # type:ignore[arg-type]

    def test_no_subtrees(self):
        with pytest.raises(ValueError):
            x509.NameConstraints(None, None)

    def test_permitted_none(self):
        excluded = [x509.DNSName("name.local")]
        nc = x509.NameConstraints(
            permitted_subtrees=None, excluded_subtrees=excluded
        )
        assert nc.permitted_subtrees is None
        assert nc.excluded_subtrees is not None

    def test_excluded_none(self):
        permitted = [x509.DNSName("name.local")]
        nc = x509.NameConstraints(
            permitted_subtrees=permitted, excluded_subtrees=None
        )
        assert nc.permitted_subtrees is not None
        assert nc.excluded_subtrees is None

    def test_iter_input(self):
        subtrees = [x509.IPAddress(ipaddress.IPv4Network("192.168.0.0/24"))]
        nc = x509.NameConstraints(iter(subtrees), iter(subtrees))
        assert list(nc.permitted_subtrees) == subtrees
        assert list(nc.excluded_subtrees) == subtrees

    def test_repr(self):
        permitted = [x509.DNSName("name.local"), x509.DNSName("name2.local")]
        nc = x509.NameConstraints(
            permitted_subtrees=permitted, excluded_subtrees=None
        )
        assert repr(nc) == (
            "<NameConstraints(permitted_subtrees=[<DNSName("
            "value='name.local')>, <DNSName(value="
            "'name2.local')>], excluded_subtrees=None)>"
        )

    def test_eq(self):
        nc = x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("name.local")],
            excluded_subtrees=[x509.DNSName("name2.local")],
        )
        nc2 = x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("name.local")],
            excluded_subtrees=[x509.DNSName("name2.local")],
        )
        assert nc == nc2

    def test_ne(self):
        nc = x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("name.local")],
            excluded_subtrees=[x509.DNSName("name2.local")],
        )
        nc2 = x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("name.local")],
            excluded_subtrees=None,
        )
        nc3 = x509.NameConstraints(
            permitted_subtrees=None,
            excluded_subtrees=[x509.DNSName("name2.local")],
        )

        assert nc != nc2
        assert nc != nc3
        assert nc != object()

    def test_hash(self):
        nc = x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("name.local")],
            excluded_subtrees=[x509.DNSName("name2.local")],
        )
        nc2 = x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("name.local")],
            excluded_subtrees=[x509.DNSName("name2.local")],
        )
        nc3 = x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("name.local")],
            excluded_subtrees=None,
        )
        nc4 = x509.NameConstraints(
            permitted_subtrees=None,
            excluded_subtrees=[x509.DNSName("name.local")],
        )
        assert hash(nc) == hash(nc2)
        assert hash(nc) != hash(nc3)
        assert hash(nc3) != hash(nc4)


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestNameConstraintsExtension(object):
    def test_permitted_excluded(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "nc_permitted_excluded_2.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        nc = cert.extensions.get_extension_for_oid(
            ExtensionOID.NAME_CONSTRAINTS
        ).value
        assert nc == x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("zombo.local")],
            excluded_subtrees=[
                x509.DirectoryName(
                    x509.Name(
                        [x509.NameAttribute(NameOID.COMMON_NAME, "zombo")]
                    )
                )
            ],
        )

    def test_permitted(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "nc_permitted_2.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        nc = cert.extensions.get_extension_for_oid(
            ExtensionOID.NAME_CONSTRAINTS
        ).value
        assert nc == x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("zombo.local")],
            excluded_subtrees=None,
        )

    def test_permitted_with_leading_period(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "nc_permitted.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        nc = cert.extensions.get_extension_for_oid(
            ExtensionOID.NAME_CONSTRAINTS
        ).value
        assert nc == x509.NameConstraints(
            permitted_subtrees=[
                x509.DNSName(".cryptography.io"),
                x509.UniformResourceIdentifier("ftp://cryptography.test"),
            ],
            excluded_subtrees=None,
        )

    def test_excluded_with_leading_period(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "nc_excluded.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        nc = cert.extensions.get_extension_for_oid(
            ExtensionOID.NAME_CONSTRAINTS
        ).value
        assert nc == x509.NameConstraints(
            permitted_subtrees=None,
            excluded_subtrees=[
                x509.DNSName(".cryptography.io"),
                x509.UniformResourceIdentifier("gopher://cryptography.test"),
            ],
        )

    def test_permitted_excluded_with_ips(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "nc_permitted_excluded.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        nc = cert.extensions.get_extension_for_oid(
            ExtensionOID.NAME_CONSTRAINTS
        ).value
        assert nc == x509.NameConstraints(
            permitted_subtrees=[
                x509.IPAddress(ipaddress.IPv4Network("192.168.0.0/24")),
                x509.IPAddress(ipaddress.IPv6Network("FF:0:0:0:0:0:0:0/96")),
            ],
            excluded_subtrees=[
                x509.DNSName(".domain.com"),
                x509.UniformResourceIdentifier("http://test.local"),
            ],
        )

    def test_single_ip_netmask(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "nc_single_ip_netmask.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        nc = cert.extensions.get_extension_for_oid(
            ExtensionOID.NAME_CONSTRAINTS
        ).value
        assert nc == x509.NameConstraints(
            permitted_subtrees=[
                x509.IPAddress(ipaddress.IPv6Network("FF:0:0:0:0:0:0:0/128")),
                x509.IPAddress(ipaddress.IPv4Network("192.168.0.1/32")),
            ],
            excluded_subtrees=None,
        )

    def test_invalid_netmask(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "nc_invalid_ip_netmask.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        with pytest.raises(ValueError):
            cert.extensions.get_extension_for_oid(
                ExtensionOID.NAME_CONSTRAINTS
            )

    def test_certbuilder(self, backend):
        permitted = [
            ".example.org",
            ".xn--4ca7aey.example.com",
            "foobar.example.net",
        ]
        private_key = RSA_KEY_2048.private_key(backend)
        builder = _make_certbuilder(private_key)
        builder = builder.add_extension(
            NameConstraints(
                permitted_subtrees=list(map(DNSName, permitted)),
                excluded_subtrees=[],
            ),
            True,
        )

        cert = builder.sign(private_key, hashes.SHA1(), backend)
        result = [
            x.value
            for x in cert.extensions.get_extension_for_class(
                NameConstraints
            ).value.permitted_subtrees
        ]
        assert result == permitted


class TestDistributionPoint(object):
    def test_distribution_point_full_name_not_general_names(self):
        with pytest.raises(TypeError):
            x509.DistributionPoint(
                ["notgn"], None, None, None  # type:ignore[list-item]
            )

    def test_distribution_point_relative_name_not_name(self):
        with pytest.raises(TypeError):
            x509.DistributionPoint(
                None, "notname", None, None  # type:ignore[arg-type]
            )

    def test_distribution_point_full_and_relative_not_none(self):
        with pytest.raises(ValueError):
            x509.DistributionPoint(
                "data", "notname", None, None  # type:ignore[arg-type]
            )

    def test_crl_issuer_not_general_names(self):
        with pytest.raises(TypeError):
            x509.DistributionPoint(
                None, None, None, ["notgn"]  # type:ignore[list-item]
            )

    def test_reason_not_reasonflags(self):
        with pytest.raises(TypeError):
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://crypt.og/crl")],
                None,
                frozenset(["notreasonflags"]),  # type:ignore[list-item]
                None,
            )

    def test_reason_not_frozenset(self):
        with pytest.raises(TypeError):
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://crypt.og/crl")],
                None,
                [x509.ReasonFlags.ca_compromise],  # type:ignore[arg-type]
                None,
            )

    def test_disallowed_reasons(self):
        with pytest.raises(ValueError):
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://crypt.og/crl")],
                None,
                frozenset([x509.ReasonFlags.unspecified]),
                None,
            )

        with pytest.raises(ValueError):
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://crypt.og/crl")],
                None,
                frozenset([x509.ReasonFlags.remove_from_crl]),
                None,
            )

    def test_reason_only(self):
        with pytest.raises(ValueError):
            x509.DistributionPoint(
                None, None, frozenset([x509.ReasonFlags.aa_compromise]), None
            )

    def test_eq(self):
        dp = x509.DistributionPoint(
            [x509.UniformResourceIdentifier("http://crypt.og/crl")],
            None,
            frozenset([x509.ReasonFlags.superseded]),
            [
                x509.DirectoryName(
                    x509.Name(
                        [
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, "Important CA"
                            )
                        ]
                    )
                )
            ],
        )
        dp2 = x509.DistributionPoint(
            [x509.UniformResourceIdentifier("http://crypt.og/crl")],
            None,
            frozenset([x509.ReasonFlags.superseded]),
            [
                x509.DirectoryName(
                    x509.Name(
                        [
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, "Important CA"
                            )
                        ]
                    )
                )
            ],
        )
        assert dp == dp2

    def test_ne(self):
        dp = x509.DistributionPoint(
            [x509.UniformResourceIdentifier("http://crypt.og/crl")],
            None,
            frozenset([x509.ReasonFlags.superseded]),
            [
                x509.DirectoryName(
                    x509.Name(
                        [
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, "Important CA"
                            )
                        ]
                    )
                )
            ],
        )
        dp2 = x509.DistributionPoint(
            [x509.UniformResourceIdentifier("http://crypt.og/crl")],
            None,
            None,
            None,
        )
        assert dp != dp2
        assert dp != object()

    def test_iter_input(self):
        name = [x509.UniformResourceIdentifier("http://crypt.og/crl")]
        issuer = [
            x509.DirectoryName(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "Important CA")]
                )
            )
        ]
        dp = x509.DistributionPoint(
            iter(name),
            None,
            frozenset([x509.ReasonFlags.ca_compromise]),
            iter(issuer),
        )
        assert list(dp.full_name) == name
        assert list(dp.crl_issuer) == issuer

    def test_repr(self):
        dp = x509.DistributionPoint(
            None,
            x509.RelativeDistinguishedName(
                [x509.NameAttribute(NameOID.COMMON_NAME, "myCN")]
            ),
            frozenset([x509.ReasonFlags.ca_compromise]),
            [
                x509.DirectoryName(
                    x509.Name(
                        [
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, "Important CA"
                            )
                        ]
                    )
                )
            ],
        )
        assert repr(dp) == (
            "<DistributionPoint(full_name=None, relative_name=<RelativeDis"
            "tinguishedName(CN=myCN)>, reasons=frozenset({<ReasonFlags.ca_"
            "compromise: 'cACompromise'>}), crl_issuer=[<DirectoryName(val"
            "ue=<Name(CN=Important CA)>)>])>"
        )

    def test_hash(self):
        dp = x509.DistributionPoint(
            [x509.UniformResourceIdentifier("http://crypt.og/crl")],
            None,
            frozenset([x509.ReasonFlags.superseded]),
            [
                x509.DirectoryName(
                    x509.Name(
                        [
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, "Important CA"
                            )
                        ]
                    )
                )
            ],
        )
        dp2 = x509.DistributionPoint(
            [x509.UniformResourceIdentifier("http://crypt.og/crl")],
            None,
            frozenset([x509.ReasonFlags.superseded]),
            [
                x509.DirectoryName(
                    x509.Name(
                        [
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, "Important CA"
                            )
                        ]
                    )
                )
            ],
        )
        dp3 = x509.DistributionPoint(
            None,
            x509.RelativeDistinguishedName(
                [x509.NameAttribute(NameOID.COMMON_NAME, "myCN")]
            ),
            None,
            None,
        )
        assert hash(dp) == hash(dp2)
        assert hash(dp) != hash(dp3)


class TestFreshestCRL(object):
    def test_invalid_distribution_points(self):
        with pytest.raises(TypeError):
            x509.FreshestCRL(
                ["notadistributionpoint"]  # type:ignore[list-item]
            )

    def test_iter_len(self):
        fcrl = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("http://domain")],
                    None,
                    None,
                    None,
                ),
            ]
        )
        assert len(fcrl) == 1
        assert list(fcrl) == [
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://domain")],
                None,
                None,
                None,
            ),
        ]

    def test_iter_input(self):
        points = [
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://domain")],
                None,
                None,
                None,
            ),
        ]
        fcrl = x509.FreshestCRL(iter(points))
        assert list(fcrl) == points

    def test_repr(self):
        fcrl = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset([x509.ReasonFlags.key_compromise]),
                    None,
                ),
            ]
        )
        assert repr(fcrl) == (
            "<FreshestCRL([<DistributionPoint(full_name=[<Unifo"
            "rmResourceIdentifier(value='ftp://domain')>], relative"
            "_name=None, reasons=frozenset({<ReasonFlags.key_compromise: "
            "'keyCompromise'>}), crl_issuer=None)>])>"
        )

    def test_eq(self):
        fcrl = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        fcrl2 = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        assert fcrl == fcrl2

    def test_ne(self):
        fcrl = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        fcrl2 = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain2")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        fcrl3 = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset([x509.ReasonFlags.key_compromise]),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        fcrl4 = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing2")],
                ),
            ]
        )
        assert fcrl != fcrl2
        assert fcrl != fcrl3
        assert fcrl != fcrl4
        assert fcrl != object()

    def test_hash(self):
        fcrl = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        fcrl2 = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        fcrl3 = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset([x509.ReasonFlags.key_compromise]),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        assert hash(fcrl) == hash(fcrl2)
        assert hash(fcrl) != hash(fcrl3)

    def test_indexing(self):
        fcrl = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    None,
                    None,
                    None,
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
                x509.DistributionPoint(
                    None,
                    None,
                    None,
                    [x509.UniformResourceIdentifier("uri://thing2")],
                ),
                x509.DistributionPoint(
                    None,
                    None,
                    None,
                    [x509.UniformResourceIdentifier("uri://thing3")],
                ),
                x509.DistributionPoint(
                    None,
                    None,
                    None,
                    [x509.UniformResourceIdentifier("uri://thing4")],
                ),
                x509.DistributionPoint(
                    None,
                    None,
                    None,
                    [x509.UniformResourceIdentifier("uri://thing5")],
                ),
            ]
        )
        assert fcrl[-1] == fcrl[4]
        assert fcrl[2:6:2] == [fcrl[2], fcrl[4]]


class TestCRLDistributionPoints(object):
    def test_invalid_distribution_points(self):
        with pytest.raises(TypeError):
            x509.CRLDistributionPoints(
                ["notadistributionpoint"],  # type:ignore[list-item]
            )

    def test_iter_len(self):
        cdp = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("http://domain")],
                    None,
                    None,
                    None,
                ),
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    None,
                ),
            ]
        )
        assert len(cdp) == 2
        assert list(cdp) == [
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://domain")],
                None,
                None,
                None,
            ),
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier("ftp://domain")],
                None,
                frozenset(
                    [
                        x509.ReasonFlags.key_compromise,
                        x509.ReasonFlags.ca_compromise,
                    ]
                ),
                None,
            ),
        ]

    def test_iter_input(self):
        points = [
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://domain")],
                None,
                None,
                None,
            ),
        ]
        cdp = x509.CRLDistributionPoints(iter(points))
        assert list(cdp) == points

    def test_repr(self):
        cdp = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset([x509.ReasonFlags.key_compromise]),
                    None,
                ),
            ]
        )
        assert repr(cdp) == (
            "<CRLDistributionPoints([<DistributionPoint(full_name=[<Unifo"
            "rmResourceIdentifier(value='ftp://domain')>], relative"
            "_name=None, reasons=frozenset({<ReasonFlags.key_compromise: "
            "'keyCompromise'>}), crl_issuer=None)>])>"
        )

    def test_eq(self):
        cdp = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        cdp2 = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        assert cdp == cdp2

    def test_ne(self):
        cdp = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        cdp2 = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain2")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        cdp3 = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset([x509.ReasonFlags.key_compromise]),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        cdp4 = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing2")],
                ),
            ]
        )
        assert cdp != cdp2
        assert cdp != cdp3
        assert cdp != cdp4
        assert cdp != object()

    def test_hash(self):
        cdp = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        cdp2 = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        cdp3 = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("ftp://domain")],
                    None,
                    frozenset([x509.ReasonFlags.key_compromise]),
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
            ]
        )
        assert hash(cdp) == hash(cdp2)
        assert hash(cdp) != hash(cdp3)

    def test_indexing(self):
        ci = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    None,
                    None,
                    None,
                    [x509.UniformResourceIdentifier("uri://thing")],
                ),
                x509.DistributionPoint(
                    None,
                    None,
                    None,
                    [x509.UniformResourceIdentifier("uri://thing2")],
                ),
                x509.DistributionPoint(
                    None,
                    None,
                    None,
                    [x509.UniformResourceIdentifier("uri://thing3")],
                ),
                x509.DistributionPoint(
                    None,
                    None,
                    None,
                    [x509.UniformResourceIdentifier("uri://thing4")],
                ),
                x509.DistributionPoint(
                    None,
                    None,
                    None,
                    [x509.UniformResourceIdentifier("uri://thing5")],
                ),
            ]
        )
        assert ci[-1] == ci[4]
        assert ci[2:6:2] == [ci[2], ci[4]]


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestCRLDistributionPointsExtension(object):
    def test_fullname_and_crl_issuer(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs", "ValidcRLIssuerTest28EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend,
        )

        cdps = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value

        assert cdps == x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.DirectoryName(
                            x509.Name(
                                [
                                    x509.NameAttribute(
                                        NameOID.COUNTRY_NAME, "US"
                                    ),
                                    x509.NameAttribute(
                                        NameOID.ORGANIZATION_NAME,
                                        "Test Certificates 2011",
                                    ),
                                    x509.NameAttribute(
                                        NameOID.ORGANIZATIONAL_UNIT_NAME,
                                        "indirectCRL CA3 cRLIssuer",
                                    ),
                                    x509.NameAttribute(
                                        NameOID.COMMON_NAME,
                                        "indirect CRL for indirectCRL CA3",
                                    ),
                                ]
                            )
                        )
                    ],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=[
                        x509.DirectoryName(
                            x509.Name(
                                [
                                    x509.NameAttribute(
                                        NameOID.COUNTRY_NAME, "US"
                                    ),
                                    x509.NameAttribute(
                                        NameOID.ORGANIZATION_NAME,
                                        "Test Certificates 2011",
                                    ),
                                    x509.NameAttribute(
                                        NameOID.ORGANIZATIONAL_UNIT_NAME,
                                        "indirectCRL CA3 cRLIssuer",
                                    ),
                                ]
                            )
                        )
                    ],
                )
            ]
        )

    def test_relativename_and_crl_issuer(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs", "ValidcRLIssuerTest29EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend,
        )

        cdps = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value

        assert cdps == x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=None,
                    relative_name=x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                NameOID.COMMON_NAME,
                                "indirect CRL for indirectCRL CA3",
                            ),
                        ]
                    ),
                    reasons=None,
                    crl_issuer=[
                        x509.DirectoryName(
                            x509.Name(
                                [
                                    x509.NameAttribute(
                                        NameOID.COUNTRY_NAME, "US"
                                    ),
                                    x509.NameAttribute(
                                        NameOID.ORGANIZATION_NAME,
                                        "Test Certificates 2011",
                                    ),
                                    x509.NameAttribute(
                                        NameOID.ORGANIZATIONAL_UNIT_NAME,
                                        "indirectCRL CA3 cRLIssuer",
                                    ),
                                ]
                            )
                        )
                    ],
                )
            ]
        )

    def test_fullname_crl_issuer_reasons(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom", "cdp_fullname_reasons_crl_issuer.pem"
            ),
            x509.load_pem_x509_certificate,
            backend,
        )

        cdps = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value

        assert cdps == x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(
                            "http://myhost.com/myca.crl"
                        )
                    ],
                    relative_name=None,
                    reasons=frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                        ]
                    ),
                    crl_issuer=[
                        x509.DirectoryName(
                            x509.Name(
                                [
                                    x509.NameAttribute(
                                        NameOID.COUNTRY_NAME, "US"
                                    ),
                                    x509.NameAttribute(
                                        NameOID.ORGANIZATION_NAME, "PyCA"
                                    ),
                                    x509.NameAttribute(
                                        NameOID.COMMON_NAME, "cryptography CA"
                                    ),
                                ]
                            )
                        )
                    ],
                )
            ]
        )

    def test_all_reasons(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "cdp_all_reasons.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )

        cdps = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value

        assert cdps == x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(
                            "http://domain.com/some.crl"
                        )
                    ],
                    relative_name=None,
                    reasons=frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                            x509.ReasonFlags.affiliation_changed,
                            x509.ReasonFlags.superseded,
                            x509.ReasonFlags.privilege_withdrawn,
                            x509.ReasonFlags.cessation_of_operation,
                            x509.ReasonFlags.aa_compromise,
                            x509.ReasonFlags.certificate_hold,
                        ]
                    ),
                    crl_issuer=None,
                )
            ]
        )

    def test_single_reason(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "cdp_reason_aa_compromise.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )

        cdps = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value

        assert cdps == x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(
                            "http://domain.com/some.crl"
                        )
                    ],
                    relative_name=None,
                    reasons=frozenset([x509.ReasonFlags.aa_compromise]),
                    crl_issuer=None,
                )
            ]
        )

    def test_crl_issuer_only(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "cdp_crl_issuer.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )

        cdps = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value

        assert cdps == x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=None,
                    relative_name=None,
                    reasons=None,
                    crl_issuer=[
                        x509.DirectoryName(
                            x509.Name(
                                [
                                    x509.NameAttribute(
                                        NameOID.COMMON_NAME, "cryptography CA"
                                    ),
                                ]
                            )
                        )
                    ],
                )
            ]
        )

    def test_crl_empty_hostname(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "cdp_empty_hostname.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )

        cdps = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value

        assert cdps == x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(
                            "ldap:///CN=A,OU=B,dc=C,DC=D?E?F?G?H=I"
                        )
                    ],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]
        )


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestFreshestCRLExtension(object):
    def test_vector(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "freshestcrl.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )

        fcrl = cert.extensions.get_extension_for_class(x509.FreshestCRL).value
        assert fcrl == x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(
                            "http://myhost.com/myca.crl"
                        ),
                        x509.UniformResourceIdentifier(
                            "http://backup.myhost.com/myca.crl"
                        ),
                    ],
                    relative_name=None,
                    reasons=frozenset(
                        [
                            x509.ReasonFlags.ca_compromise,
                            x509.ReasonFlags.key_compromise,
                        ]
                    ),
                    crl_issuer=[
                        x509.DirectoryName(
                            x509.Name(
                                [
                                    x509.NameAttribute(
                                        NameOID.COUNTRY_NAME, "US"
                                    ),
                                    x509.NameAttribute(
                                        NameOID.COMMON_NAME, "cryptography CA"
                                    ),
                                ]
                            )
                        )
                    ],
                )
            ]
        )


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestOCSPNoCheckExtension(object):
    def test_nocheck(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "ocsp_nocheck.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.OCSP_NO_CHECK)
        assert isinstance(ext.value, x509.OCSPNoCheck)

    def test_eq(self):
        onc1 = x509.OCSPNoCheck()
        onc2 = x509.OCSPNoCheck()

        assert onc1 == onc2

    def test_hash(self):
        onc1 = x509.OCSPNoCheck()
        onc2 = x509.OCSPNoCheck()

        assert hash(onc1) == hash(onc2)

    def test_ne(self):
        onc1 = x509.OCSPNoCheck()
        onc2 = x509.OCSPNoCheck()

        assert onc1 == onc2
        assert (onc1 != onc2) is False
        assert onc1 != object()

    def test_repr(self):
        onc = x509.OCSPNoCheck()

        assert repr(onc) == "<OCSPNoCheck()>"


class TestInhibitAnyPolicy(object):
    def test_not_int(self):
        with pytest.raises(TypeError):
            x509.InhibitAnyPolicy("notint")  # type:ignore[arg-type]

    def test_negative_int(self):
        with pytest.raises(ValueError):
            x509.InhibitAnyPolicy(-1)

    def test_repr(self):
        iap = x509.InhibitAnyPolicy(0)
        assert repr(iap) == "<InhibitAnyPolicy(skip_certs=0)>"

    def test_eq(self):
        iap = x509.InhibitAnyPolicy(1)
        iap2 = x509.InhibitAnyPolicy(1)
        assert iap == iap2

    def test_ne(self):
        iap = x509.InhibitAnyPolicy(1)
        iap2 = x509.InhibitAnyPolicy(4)
        assert iap != iap2
        assert iap != object()

    def test_hash(self):
        iap = x509.InhibitAnyPolicy(1)
        iap2 = x509.InhibitAnyPolicy(1)
        iap3 = x509.InhibitAnyPolicy(4)
        assert hash(iap) == hash(iap2)
        assert hash(iap) != hash(iap3)


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestInhibitAnyPolicyExtension(object):
    def test_inhibit_any_policy(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "inhibit_any_policy_5.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        iap = cert.extensions.get_extension_for_oid(
            ExtensionOID.INHIBIT_ANY_POLICY
        ).value
        assert iap.skip_certs == 5


class TestIssuingDistributionPointExtension(object):
    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            (
                "crl_idp_fullname_indirect_crl.pem",
                x509.IssuingDistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(
                            "http://myhost.com/myca.crl"
                        )
                    ],
                    relative_name=None,
                    only_contains_user_certs=False,
                    only_contains_ca_certs=False,
                    only_some_reasons=None,
                    indirect_crl=True,
                    only_contains_attribute_certs=False,
                ),
            ),
            (
                "crl_idp_fullname_only.pem",
                x509.IssuingDistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(
                            "http://myhost.com/myca.crl"
                        )
                    ],
                    relative_name=None,
                    only_contains_user_certs=False,
                    only_contains_ca_certs=False,
                    only_some_reasons=None,
                    indirect_crl=False,
                    only_contains_attribute_certs=False,
                ),
            ),
            (
                "crl_idp_fullname_only_aa.pem",
                x509.IssuingDistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(
                            "http://myhost.com/myca.crl"
                        )
                    ],
                    relative_name=None,
                    only_contains_user_certs=False,
                    only_contains_ca_certs=False,
                    only_some_reasons=None,
                    indirect_crl=False,
                    only_contains_attribute_certs=True,
                ),
            ),
            (
                "crl_idp_fullname_only_user.pem",
                x509.IssuingDistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(
                            "http://myhost.com/myca.crl"
                        )
                    ],
                    relative_name=None,
                    only_contains_user_certs=True,
                    only_contains_ca_certs=False,
                    only_some_reasons=None,
                    indirect_crl=False,
                    only_contains_attribute_certs=False,
                ),
            ),
            (
                "crl_idp_only_ca.pem",
                x509.IssuingDistributionPoint(
                    full_name=None,
                    relative_name=x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                oid=x509.NameOID.ORGANIZATION_NAME,
                                value="PyCA",
                            )
                        ]
                    ),
                    only_contains_user_certs=False,
                    only_contains_ca_certs=True,
                    only_some_reasons=None,
                    indirect_crl=False,
                    only_contains_attribute_certs=False,
                ),
            ),
            (
                "crl_idp_reasons_only.pem",
                x509.IssuingDistributionPoint(
                    full_name=None,
                    relative_name=None,
                    only_contains_user_certs=False,
                    only_contains_ca_certs=False,
                    only_some_reasons=frozenset(
                        [x509.ReasonFlags.key_compromise]
                    ),
                    indirect_crl=False,
                    only_contains_attribute_certs=False,
                ),
            ),
            (
                "crl_idp_relative_user_all_reasons.pem",
                x509.IssuingDistributionPoint(
                    full_name=None,
                    relative_name=x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                oid=x509.NameOID.ORGANIZATION_NAME,
                                value="PyCA",
                            )
                        ]
                    ),
                    only_contains_user_certs=True,
                    only_contains_ca_certs=False,
                    only_some_reasons=frozenset(
                        [
                            x509.ReasonFlags.key_compromise,
                            x509.ReasonFlags.ca_compromise,
                            x509.ReasonFlags.affiliation_changed,
                            x509.ReasonFlags.superseded,
                            x509.ReasonFlags.cessation_of_operation,
                            x509.ReasonFlags.certificate_hold,
                            x509.ReasonFlags.privilege_withdrawn,
                            x509.ReasonFlags.aa_compromise,
                        ]
                    ),
                    indirect_crl=False,
                    only_contains_attribute_certs=False,
                ),
            ),
            (
                "crl_idp_relativename_only.pem",
                x509.IssuingDistributionPoint(
                    full_name=None,
                    relative_name=x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                oid=x509.NameOID.ORGANIZATION_NAME,
                                value="PyCA",
                            )
                        ]
                    ),
                    only_contains_user_certs=False,
                    only_contains_ca_certs=False,
                    only_some_reasons=None,
                    indirect_crl=False,
                    only_contains_attribute_certs=False,
                ),
            ),
        ],
    )
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_vectors(self, filename, expected, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", filename),
            x509.load_pem_x509_crl,
            backend,
        )
        idp = crl.extensions.get_extension_for_class(
            x509.IssuingDistributionPoint
        ).value
        assert idp == expected

    @pytest.mark.parametrize(
        (
            "error",
            "only_contains_user_certs",
            "only_contains_ca_certs",
            "indirect_crl",
            "only_contains_attribute_certs",
            "only_some_reasons",
            "full_name",
            "relative_name",
        ),
        [
            (
                TypeError,
                False,
                False,
                False,
                False,
                "notafrozenset",
                None,
                None,
            ),
            (
                TypeError,
                False,
                False,
                False,
                False,
                frozenset(["bad"]),
                None,
                None,
            ),
            (
                ValueError,
                False,
                False,
                False,
                False,
                frozenset([x509.ReasonFlags.unspecified]),
                None,
                None,
            ),
            (
                ValueError,
                False,
                False,
                False,
                False,
                frozenset([x509.ReasonFlags.remove_from_crl]),
                None,
                None,
            ),
            (TypeError, "notabool", False, False, False, None, None, None),
            (TypeError, False, "notabool", False, False, None, None, None),
            (TypeError, False, False, "notabool", False, None, None, None),
            (TypeError, False, False, False, "notabool", None, None, None),
            (ValueError, True, True, False, False, None, None, None),
            (ValueError, False, False, True, True, None, None, None),
            (ValueError, False, False, False, False, None, None, None),
        ],
    )
    def test_invalid_init(
        self,
        error,
        only_contains_user_certs,
        only_contains_ca_certs,
        indirect_crl,
        only_contains_attribute_certs,
        only_some_reasons,
        full_name,
        relative_name,
    ):
        with pytest.raises(error):
            x509.IssuingDistributionPoint(
                full_name,
                relative_name,
                only_contains_user_certs,
                only_contains_ca_certs,
                only_some_reasons,
                indirect_crl,
                only_contains_attribute_certs,
            )

    def test_repr(self):
        idp = x509.IssuingDistributionPoint(
            None,
            None,
            False,
            False,
            frozenset([x509.ReasonFlags.key_compromise]),
            False,
            False,
        )
        assert repr(idp) == (
            "<IssuingDistributionPoint(full_name=None, relative_name=None,"
            " only_contains_user_certs=False, only_contains_ca_certs=False"
            ", only_some_reasons=frozenset({<ReasonFlags.key_compromise: '"
            "keyCompromise'>}), indirect_crl=False, only_contains_attribut"
            "e_certs=False)>"
        )

    def test_eq(self):
        idp1 = x509.IssuingDistributionPoint(
            only_contains_user_certs=False,
            only_contains_ca_certs=False,
            indirect_crl=False,
            only_contains_attribute_certs=False,
            only_some_reasons=None,
            full_name=None,
            relative_name=x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(
                        oid=x509.NameOID.ORGANIZATION_NAME, value="PyCA"
                    )
                ]
            ),
        )
        idp2 = x509.IssuingDistributionPoint(
            only_contains_user_certs=False,
            only_contains_ca_certs=False,
            indirect_crl=False,
            only_contains_attribute_certs=False,
            only_some_reasons=None,
            full_name=None,
            relative_name=x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(
                        oid=x509.NameOID.ORGANIZATION_NAME, value="PyCA"
                    )
                ]
            ),
        )
        assert idp1 == idp2

    def test_ne(self):
        idp1 = x509.IssuingDistributionPoint(
            only_contains_user_certs=False,
            only_contains_ca_certs=False,
            indirect_crl=False,
            only_contains_attribute_certs=False,
            only_some_reasons=None,
            full_name=None,
            relative_name=x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(
                        oid=x509.NameOID.ORGANIZATION_NAME, value="PyCA"
                    )
                ]
            ),
        )
        idp2 = x509.IssuingDistributionPoint(
            only_contains_user_certs=True,
            only_contains_ca_certs=False,
            indirect_crl=False,
            only_contains_attribute_certs=False,
            only_some_reasons=None,
            full_name=None,
            relative_name=x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(
                        oid=x509.NameOID.ORGANIZATION_NAME, value="PyCA"
                    )
                ]
            ),
        )
        assert idp1 != idp2
        assert idp1 != object()

    def test_hash(self):
        idp1 = x509.IssuingDistributionPoint(
            None, None, True, False, None, False, False
        )
        idp2 = x509.IssuingDistributionPoint(
            None, None, True, False, None, False, False
        )
        idp3 = x509.IssuingDistributionPoint(
            None,
            x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(
                        oid=x509.NameOID.ORGANIZATION_NAME, value="PyCA"
                    )
                ]
            ),
            True,
            False,
            None,
            False,
            False,
        )
        assert hash(idp1) == hash(idp2)
        assert hash(idp1) != hash(idp3)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    @pytest.mark.parametrize(
        "idp",
        [
            x509.IssuingDistributionPoint(
                full_name=[
                    x509.UniformResourceIdentifier(
                        "http://myhost.com/myca.crl"
                    )
                ],
                relative_name=None,
                only_contains_user_certs=False,
                only_contains_ca_certs=False,
                only_some_reasons=None,
                indirect_crl=True,
                only_contains_attribute_certs=False,
            ),
            x509.IssuingDistributionPoint(
                full_name=[
                    x509.UniformResourceIdentifier(
                        "http://myhost.com/myca.crl"
                    )
                ],
                relative_name=None,
                only_contains_user_certs=False,
                only_contains_ca_certs=False,
                only_some_reasons=None,
                indirect_crl=False,
                only_contains_attribute_certs=False,
            ),
            x509.IssuingDistributionPoint(
                full_name=[
                    x509.UniformResourceIdentifier(
                        "http://myhost.com/myca.crl"
                    )
                ],
                relative_name=None,
                only_contains_user_certs=False,
                only_contains_ca_certs=False,
                only_some_reasons=None,
                indirect_crl=False,
                only_contains_attribute_certs=True,
            ),
            x509.IssuingDistributionPoint(
                full_name=[
                    x509.UniformResourceIdentifier(
                        "http://myhost.com/myca.crl"
                    )
                ],
                relative_name=None,
                only_contains_user_certs=True,
                only_contains_ca_certs=False,
                only_some_reasons=None,
                indirect_crl=False,
                only_contains_attribute_certs=False,
            ),
            x509.IssuingDistributionPoint(
                full_name=None,
                relative_name=x509.RelativeDistinguishedName(
                    [
                        x509.NameAttribute(
                            oid=x509.NameOID.ORGANIZATION_NAME, value="PyCA"
                        )
                    ]
                ),
                only_contains_user_certs=False,
                only_contains_ca_certs=True,
                only_some_reasons=None,
                indirect_crl=False,
                only_contains_attribute_certs=False,
            ),
            x509.IssuingDistributionPoint(
                full_name=None,
                relative_name=None,
                only_contains_user_certs=False,
                only_contains_ca_certs=True,
                only_some_reasons=frozenset([x509.ReasonFlags.key_compromise]),
                indirect_crl=False,
                only_contains_attribute_certs=False,
            ),
            x509.IssuingDistributionPoint(
                full_name=None,
                relative_name=x509.RelativeDistinguishedName(
                    [
                        x509.NameAttribute(
                            oid=x509.NameOID.ORGANIZATION_NAME, value="PyCA"
                        ),
                        x509.NameAttribute(
                            oid=x509.NameOID.COMMON_NAME, value="cryptography"
                        ),
                    ]
                ),
                only_contains_user_certs=True,
                only_contains_ca_certs=False,
                only_some_reasons=frozenset(
                    [
                        x509.ReasonFlags.key_compromise,
                        x509.ReasonFlags.ca_compromise,
                        x509.ReasonFlags.affiliation_changed,
                        x509.ReasonFlags.privilege_withdrawn,
                        x509.ReasonFlags.aa_compromise,
                    ]
                ),
                indirect_crl=False,
                only_contains_attribute_certs=False,
            ),
            x509.IssuingDistributionPoint(
                full_name=None,
                relative_name=x509.RelativeDistinguishedName(
                    [
                        x509.NameAttribute(
                            oid=x509.NameOID.ORGANIZATION_NAME, value="PyCA"
                        )
                    ]
                ),
                only_contains_user_certs=False,
                only_contains_ca_certs=False,
                only_some_reasons=None,
                indirect_crl=False,
                only_contains_attribute_certs=False,
            ),
        ],
    )
    def test_generate(self, idp, backend):
        key = RSA_KEY_2048.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
            .add_extension(idp, True)
        )

        crl = builder.sign(key, hashes.SHA256(), backend)
        ext = crl.extensions.get_extension_for_class(
            x509.IssuingDistributionPoint
        )
        assert ext.critical is True
        assert ext.value == idp


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestPrecertPoisonExtension(object):
    def test_load(self, backend):
        cert = _load_cert(
            os.path.join("x509", "cryptography.io.precert.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        poison = cert.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_POISON
        ).value
        assert isinstance(poison, x509.PrecertPoison)
        poison = cert.extensions.get_extension_for_class(
            x509.PrecertPoison
        ).value
        assert isinstance(poison, x509.PrecertPoison)

    def test_generate(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        cert = (
            _make_certbuilder(private_key)
            .add_extension(x509.PrecertPoison(), critical=True)
            .sign(private_key, hashes.SHA256(), backend)
        )
        poison = cert.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_POISON
        ).value
        assert isinstance(poison, x509.PrecertPoison)

    def test_eq(self):
        pcp1 = x509.PrecertPoison()
        pcp2 = x509.PrecertPoison()

        assert pcp1 == pcp2

    def test_hash(self):
        pcp1 = x509.PrecertPoison()
        pcp2 = x509.PrecertPoison()

        assert hash(pcp1) == hash(pcp2)

    def test_ne(self):
        pcp1 = x509.PrecertPoison()
        pcp2 = x509.PrecertPoison()

        assert pcp1 == pcp2
        assert (pcp1 != pcp2) is False
        assert pcp1 != object()

    def test_repr(self):
        pcp = x509.PrecertPoison()

        assert repr(pcp) == "<PrecertPoison()>"


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestSignedCertificateTimestamps(object):
    @pytest.mark.supported(
        only_if=lambda backend: (backend._lib.Cryptography_HAS_SCT),
        skip_message="Requires CT support",
    )
    def test_eq(self, backend):
        sct = (
            _load_cert(
                os.path.join("x509", "badssl-sct.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value[0]
        )
        sct2 = (
            _load_cert(
                os.path.join("x509", "badssl-sct.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value[0]
        )
        assert sct == sct2

    @pytest.mark.supported(
        only_if=lambda backend: (backend._lib.Cryptography_HAS_SCT),
        skip_message="Requires CT support",
    )
    def test_ne(self, backend):
        sct = (
            _load_cert(
                os.path.join("x509", "badssl-sct.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value[0]
        )
        sct2 = (
            _load_cert(
                os.path.join("x509", "cryptography-scts.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value[0]
        )
        assert sct != sct2
        assert sct != object()

    @pytest.mark.supported(
        only_if=lambda backend: (backend._lib.Cryptography_HAS_SCT),
        skip_message="Requires CT support",
    )
    def test_hash(self, backend):
        sct = (
            _load_cert(
                os.path.join("x509", "badssl-sct.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value[0]
        )
        sct2 = (
            _load_cert(
                os.path.join("x509", "badssl-sct.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value[0]
        )
        sct3 = (
            _load_cert(
                os.path.join("x509", "cryptography-scts.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value[0]
        )
        assert hash(sct) == hash(sct2)
        assert hash(sct) != hash(sct3)


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestPrecertificateSignedCertificateTimestampsExtension(object):
    def test_init(self):
        with pytest.raises(TypeError):
            x509.PrecertificateSignedCertificateTimestamps(
                [object()]  # type:ignore[list-item]
            )

    def test_repr(self):
        assert repr(x509.PrecertificateSignedCertificateTimestamps([])) == (
            "<PrecertificateSignedCertificateTimestamps([])>"
        )

    @pytest.mark.supported(
        only_if=lambda backend: (backend._lib.Cryptography_HAS_SCT),
        skip_message="Requires CT support",
    )
    def test_eq(self, backend):
        psct1 = (
            _load_cert(
                os.path.join("x509", "badssl-sct.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value
        )
        psct2 = (
            _load_cert(
                os.path.join("x509", "badssl-sct.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value
        )
        assert psct1 == psct2

    @pytest.mark.supported(
        only_if=lambda backend: (backend._lib.Cryptography_HAS_SCT),
        skip_message="Requires CT support",
    )
    def test_ne(self, backend):
        psct1 = (
            _load_cert(
                os.path.join("x509", "cryptography-scts.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value
        )
        psct2 = (
            _load_cert(
                os.path.join("x509", "badssl-sct.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value
        )
        assert psct1 != psct2
        assert psct1 != object()

    @pytest.mark.supported(
        only_if=lambda backend: (backend._lib.Cryptography_HAS_SCT),
        skip_message="Requires CT support",
    )
    def test_hash(self, backend):
        psct1 = (
            _load_cert(
                os.path.join("x509", "badssl-sct.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value
        )
        psct2 = (
            _load_cert(
                os.path.join("x509", "badssl-sct.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value
        )
        psct3 = (
            _load_cert(
                os.path.join("x509", "cryptography-scts.pem"),
                x509.load_pem_x509_certificate,
                backend,
            )
            .extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
            .value
        )
        assert hash(psct1) == hash(psct2)
        assert hash(psct1) != hash(psct3)

    @pytest.mark.supported(
        only_if=lambda backend: (backend._lib.Cryptography_HAS_SCT),
        skip_message="Requires CT support",
    )
    def test_simple(self, backend):
        cert = _load_cert(
            os.path.join("x509", "badssl-sct.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        scts = cert.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        ).value
        assert len(scts) == 1
        [sct] = scts
        assert scts[0] == sct
        assert sct.version == x509.certificate_transparency.Version.v1
        assert sct.log_id == (
            b"\xa7\xceJNb\x07\xe0\xad\xde\xe5\xfd\xaaK\x1f\x86v\x87g\xb5\xd0"
            b"\x02\xa5]G1\x0e~g\n\x95\xea\xb2"
        )
        assert sct.timestamp == datetime.datetime(
            2016, 11, 17, 1, 56, 25, 396000
        )
        assert (
            sct.entry_type
            == x509.certificate_transparency.LogEntryType.PRE_CERTIFICATE
        )

    @pytest.mark.supported(
        only_if=lambda backend: (backend._lib.Cryptography_HAS_SCT),
        skip_message="Requires CT support",
    )
    def test_generate(self, backend):
        cert = _load_cert(
            os.path.join("x509", "badssl-sct.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        scts = cert.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        ).value
        assert len(scts) == 1
        [sct] = scts

        private_key = RSA_KEY_2048.private_key(backend)
        builder = _make_certbuilder(private_key).add_extension(
            x509.PrecertificateSignedCertificateTimestamps([sct]),
            critical=False,
        )
        cert = builder.sign(private_key, hashes.SHA256(), backend)
        ext = cert.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        ).value
        assert list(ext) == [sct]

    @pytest.mark.supported(
        only_if=lambda backend: backend._lib.CRYPTOGRAPHY_IS_LIBRESSL,
        skip_message="Requires LibreSSL",
    )
    def test_skips_scts_if_unsupported(self, backend):
        cert = _load_cert(
            os.path.join("x509", "badssl-sct.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        assert len(cert.extensions) == 10
        with pytest.raises(x509.ExtensionNotFound):
            cert.extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )

        ext = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
        )
        assert isinstance(ext.value, x509.UnrecognizedExtension)


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestInvalidExtension(object):
    def test_invalid_certificate_policies_data(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "cp_invalid.pem"),
            x509.load_pem_x509_certificate,
            backend,
        )
        with pytest.raises(ValueError):
            cert.extensions


class TestOCSPNonce(object):
    def test_non_bytes(self):
        with pytest.raises(TypeError):
            x509.OCSPNonce(38)  # type:ignore[arg-type]

    def test_eq(self):
        nonce1 = x509.OCSPNonce(b"0" * 5)
        nonce2 = x509.OCSPNonce(b"0" * 5)
        assert nonce1 == nonce2

    def test_ne(self):
        nonce1 = x509.OCSPNonce(b"0" * 5)
        nonce2 = x509.OCSPNonce(b"0" * 6)
        assert nonce1 != nonce2
        assert nonce1 != object()

    def test_repr(self):
        nonce1 = x509.OCSPNonce(b"nonce")
        assert repr(nonce1) == "<OCSPNonce(nonce=b'nonce')>"

    def test_hash(self):
        nonce1 = x509.OCSPNonce(b"0" * 5)
        nonce2 = x509.OCSPNonce(b"0" * 5)
        nonce3 = x509.OCSPNonce(b"1" * 5)
        assert hash(nonce1) == hash(nonce2)
        assert hash(nonce1) != hash(nonce3)


def test_all_extension_oid_members_have_names_defined():
    for oid in dir(ExtensionOID):
        if oid.startswith("__"):
            continue
        assert getattr(ExtensionOID, oid) in _OID_NAMES
