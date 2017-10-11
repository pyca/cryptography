# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import datetime
import ipaddress
import os
import sys

from asn1crypto.x509 import Certificate

import pytest

import pytz

import six

from cryptography import utils, x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.interfaces import (
    DSABackend, EllipticCurveBackend, RSABackend, X509Backend
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature
)
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import (
    AuthorityInformationAccessOID, ExtendedKeyUsageOID, ExtensionOID,
    NameOID, SignatureAlgorithmOID
)

from ..hazmat.primitives.fixtures_dsa import DSA_KEY_2048
from ..hazmat.primitives.fixtures_ec import EC_KEY_SECP256R1
from ..hazmat.primitives.fixtures_rsa import RSA_KEY_2048, RSA_KEY_512
from ..hazmat.primitives.test_ec import _skip_curve_unsupported
from ..utils import load_vectors_from_file


@utils.register_interface(x509.ExtensionType)
class DummyExtension(object):
    oid = x509.ObjectIdentifier("1.2.3.4")


@utils.register_interface(x509.GeneralName)
class FakeGeneralName(object):
    def __init__(self, value):
        self._value = value

    value = utils.read_only_property("_value")


def _load_cert(filename, loader, backend):
    cert = load_vectors_from_file(
        filename=filename,
        loader=lambda pemfile: loader(pemfile.read(), backend),
        mode="rb"
    )
    return cert


@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestCertificateRevocationList(object):
    def test_load_pem_crl(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_all_reasons.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        assert isinstance(crl, x509.CertificateRevocationList)
        fingerprint = binascii.hexlify(crl.fingerprint(hashes.SHA1()))
        assert fingerprint == b"3234b0cb4c0cedf6423724b736729dcfc9e441ef"
        assert isinstance(crl.signature_hash_algorithm, hashes.SHA256)
        assert (
            crl.signature_algorithm_oid ==
            SignatureAlgorithmOID.RSA_WITH_SHA256
        )

    def test_load_der_crl(self, backend):
        crl = _load_cert(
            os.path.join("x509", "PKITS_data", "crls", "GoodCACRL.crl"),
            x509.load_der_x509_crl,
            backend
        )

        assert isinstance(crl, x509.CertificateRevocationList)
        fingerprint = binascii.hexlify(crl.fingerprint(hashes.SHA1()))
        assert fingerprint == b"dd3db63c50f4c4a13e090f14053227cb1011a5ad"
        assert isinstance(crl.signature_hash_algorithm, hashes.SHA256)

    def test_invalid_pem(self, backend):
        with pytest.raises(ValueError):
            x509.load_pem_x509_crl(b"notacrl", backend)

    def test_invalid_der(self, backend):
        with pytest.raises(ValueError):
            x509.load_der_x509_crl(b"notacrl", backend)

    def test_unknown_signature_algorithm(self, backend):
        crl = _load_cert(
            os.path.join(
                "x509", "custom", "crl_md2_unknown_crit_entry_ext.pem"
            ),
            x509.load_pem_x509_crl,
            backend
        )

        with pytest.raises(UnsupportedAlgorithm):
                crl.signature_hash_algorithm()

    def test_issuer(self, backend):
        crl = _load_cert(
            os.path.join("x509", "PKITS_data", "crls", "GoodCACRL.crl"),
            x509.load_der_x509_crl,
            backend
        )

        assert isinstance(crl.issuer, x509.Name)
        assert list(crl.issuer) == [
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(
                x509.OID_ORGANIZATION_NAME, u'Test Certificates 2011'
            ),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'Good CA')
        ]
        assert crl.issuer.get_attributes_for_oid(x509.OID_COMMON_NAME) == [
            x509.NameAttribute(x509.OID_COMMON_NAME, u'Good CA')
        ]

    def test_equality(self, backend):
        crl1 = _load_cert(
            os.path.join("x509", "PKITS_data", "crls", "GoodCACRL.crl"),
            x509.load_der_x509_crl,
            backend
        )

        crl2 = _load_cert(
            os.path.join("x509", "PKITS_data", "crls", "GoodCACRL.crl"),
            x509.load_der_x509_crl,
            backend
        )

        crl3 = _load_cert(
            os.path.join("x509", "custom", "crl_all_reasons.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        assert crl1 == crl2
        assert crl1 != crl3
        assert crl1 != object()

    def test_update_dates(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_all_reasons.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        assert isinstance(crl.next_update, datetime.datetime)
        assert isinstance(crl.last_update, datetime.datetime)

        assert crl.next_update.isoformat() == "2016-01-01T00:00:00"
        assert crl.last_update.isoformat() == "2015-01-01T00:00:00"

    def test_revoked_cert_retrieval(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_all_reasons.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        for r in crl:
            assert isinstance(r, x509.RevokedCertificate)

        # Check that len() works for CRLs.
        assert len(crl) == 12

    def test_revoked_cert_retrieval_retain_only_revoked(self, backend):
        """
        This test attempts to trigger the crash condition described in
        https://github.com/pyca/cryptography/issues/2557
        PyPy does gc at its own pace, so it will only be reliable on CPython.
        """
        revoked = _load_cert(
            os.path.join("x509", "custom", "crl_all_reasons.pem"),
            x509.load_pem_x509_crl,
            backend
        )[11]
        assert revoked.revocation_date == datetime.datetime(2015, 1, 1, 0, 0)
        assert revoked.serial_number == 11

    def test_extensions(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_ian_aia_aki.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        crl_number = crl.extensions.get_extension_for_oid(
            ExtensionOID.CRL_NUMBER
        )
        aki = crl.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        )
        aia = crl.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        )
        ian = crl.extensions.get_extension_for_class(
            x509.IssuerAlternativeName
        )
        assert crl_number.value == x509.CRLNumber(1)
        assert crl_number.critical is False
        assert aki.value == x509.AuthorityKeyIdentifier(
            key_identifier=(
                b'yu\xbb\x84:\xcb,\xdez\t\xbe1\x1bC\xbc\x1c*MSX'
            ),
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        )
        assert aia.value == x509.AuthorityInformationAccess([
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.DNSName(u"cryptography.io")
            )
        ])
        assert ian.value == x509.IssuerAlternativeName([
            x509.UniformResourceIdentifier(u"https://cryptography.io"),
        ])

    def test_delta_crl_indicator(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_delta_crl_indicator.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        dci = crl.extensions.get_extension_for_oid(
            ExtensionOID.DELTA_CRL_INDICATOR
        )
        assert dci.value == x509.DeltaCRLIndicator(12345678901234567890)
        assert dci.critical is False

    def test_signature(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_all_reasons.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        assert crl.signature == binascii.unhexlify(
            b"536a5a0794f68267361e7bc2f19167a3e667a2ab141535616855d8deb2ba1af"
            b"9fd4546b1fe76b454eb436af7b28229fedff4634dfc9dd92254266219ae0ea8"
            b"75d9ff972e9a2da23d5945f073da18c50a4265bfed9ca16586347800ef49dd1"
            b"6856d7265f4f3c498a57f04dc04404e2bd2e2ada1f5697057aacef779a18371"
            b"c621edc9a5c2b8ec1716e8fa22feeb7fcec0ce9156c8d344aa6ae8d1a5d99d0"
            b"9386df36307df3b63c83908f4a61a0ff604c1e292ad63b349d1082ddd7ae1b7"
            b"c178bba995523ec6999310c54da5706549797bfb1230f5593ba7b4353dade4f"
            b"d2be13a57580a6eb20b5c4083f000abac3bf32cd8b75f23e4c8f4b3a79e1e2d"
            b"58a472b0"
        )

    def test_tbs_certlist_bytes(self, backend):
        crl = _load_cert(
            os.path.join("x509", "PKITS_data", "crls", "GoodCACRL.crl"),
            x509.load_der_x509_crl,
            backend
        )

        ca_cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )

        verifier = ca_cert.public_key().verifier(
            crl.signature, padding.PKCS1v15(), crl.signature_hash_algorithm
        )
        verifier.update(crl.tbs_certlist_bytes)
        verifier.verify()

    def test_public_bytes_pem(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_empty.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        # Encode it to PEM and load it back.
        crl = x509.load_pem_x509_crl(crl.public_bytes(
            encoding=serialization.Encoding.PEM,
        ), backend)

        assert len(crl) == 0
        assert crl.last_update == datetime.datetime(2015, 12, 20, 23, 44, 47)
        assert crl.next_update == datetime.datetime(2015, 12, 28, 0, 44, 47)

    def test_public_bytes_der(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_all_reasons.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        # Encode it to DER and load it back.
        crl = x509.load_der_x509_crl(crl.public_bytes(
            encoding=serialization.Encoding.DER,
        ), backend)

        assert len(crl) == 12
        assert crl.last_update == datetime.datetime(2015, 1, 1, 0, 0, 0)
        assert crl.next_update == datetime.datetime(2016, 1, 1, 0, 0, 0)

    @pytest.mark.parametrize(
        ("cert_path", "loader_func", "encoding"),
        [
            (
                os.path.join("x509", "custom", "crl_all_reasons.pem"),
                x509.load_pem_x509_crl,
                serialization.Encoding.PEM,
            ),
            (
                os.path.join("x509", "PKITS_data", "crls", "GoodCACRL.crl"),
                x509.load_der_x509_crl,
                serialization.Encoding.DER,
            ),
        ]
    )
    def test_public_bytes_match(self, cert_path, loader_func, encoding,
                                backend):
        crl_bytes = load_vectors_from_file(
            cert_path, lambda pemfile: pemfile.read(), mode="rb"
        )
        crl = loader_func(crl_bytes, backend)
        serialized = crl.public_bytes(encoding)
        assert serialized == crl_bytes

    def test_public_bytes_invalid_encoding(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_empty.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        with pytest.raises(TypeError):
            crl.public_bytes('NotAnEncoding')

    def test_verify_bad(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "invalid_signature.pem"),
            x509.load_pem_x509_crl,
            backend
        )
        crt = _load_cert(
            os.path.join("x509", "custom", "invalid_signature.pem"),
            x509.load_pem_x509_certificate,
            backend
        )

        assert not crl.is_signature_valid(crt.public_key())

    def test_verify_good(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "valid_signature.pem"),
            x509.load_pem_x509_crl,
            backend
        )
        crt = _load_cert(
            os.path.join("x509", "custom", "valid_signature.pem"),
            x509.load_pem_x509_certificate,
            backend
        )

        assert crl.is_signature_valid(crt.public_key())

    def test_verify_argument_must_be_a_public_key(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "valid_signature.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        with pytest.raises(TypeError):
            crl.is_signature_valid("not a public key")

        with pytest.raises(TypeError):
            crl.is_signature_valid(object)


@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestRevokedCertificate(object):
    def test_revoked_basics(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_all_reasons.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        for i, rev in enumerate(crl):
            assert isinstance(rev, x509.RevokedCertificate)
            assert isinstance(rev.serial_number, int)
            assert isinstance(rev.revocation_date, datetime.datetime)
            assert isinstance(rev.extensions, x509.Extensions)

            assert rev.serial_number == i
            assert rev.revocation_date.isoformat() == "2015-01-01T00:00:00"

    def test_revoked_extensions(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_all_reasons.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        exp_issuer = [
            x509.DirectoryName(x509.Name([
                x509.NameAttribute(x509.OID_COUNTRY_NAME, u"US"),
                x509.NameAttribute(x509.OID_COMMON_NAME, u"cryptography.io"),
            ]))
        ]

        # First revoked cert doesn't have extensions, test if it is handled
        # correctly.
        rev0 = crl[0]
        # It should return an empty Extensions object.
        assert isinstance(rev0.extensions, x509.Extensions)
        assert len(rev0.extensions) == 0
        with pytest.raises(x509.ExtensionNotFound):
            rev0.extensions.get_extension_for_oid(x509.OID_CRL_REASON)
        with pytest.raises(x509.ExtensionNotFound):
            rev0.extensions.get_extension_for_oid(x509.OID_CERTIFICATE_ISSUER)
        with pytest.raises(x509.ExtensionNotFound):
            rev0.extensions.get_extension_for_oid(x509.OID_INVALIDITY_DATE)

        # Test manual retrieval of extension values.
        rev1 = crl[1]
        assert isinstance(rev1.extensions, x509.Extensions)

        reason = rev1.extensions.get_extension_for_class(
            x509.CRLReason).value
        assert reason == x509.CRLReason(x509.ReasonFlags.unspecified)

        issuer = rev1.extensions.get_extension_for_class(
            x509.CertificateIssuer).value
        assert issuer == x509.CertificateIssuer(exp_issuer)

        date = rev1.extensions.get_extension_for_class(
            x509.InvalidityDate).value
        assert date == x509.InvalidityDate(datetime.datetime(2015, 1, 1, 0, 0))

        # Check if all reason flags can be found in the CRL.
        flags = set(x509.ReasonFlags)
        for rev in crl:
            try:
                r = rev.extensions.get_extension_for_class(x509.CRLReason)
            except x509.ExtensionNotFound:
                # Not all revoked certs have a reason extension.
                pass
            else:
                flags.discard(r.value.reason)

        assert len(flags) == 0

    def test_no_revoked_certs(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_empty.pem"),
            x509.load_pem_x509_crl,
            backend
        )
        assert len(crl) == 0

    def test_duplicate_entry_ext(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_dup_entry_ext.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        with pytest.raises(x509.DuplicateExtension):
            crl[0].extensions

    def test_unsupported_crit_entry_ext(self, backend):
        crl = _load_cert(
            os.path.join(
                "x509", "custom", "crl_md2_unknown_crit_entry_ext.pem"
            ),
            x509.load_pem_x509_crl,
            backend
        )

        ext = crl[0].extensions.get_extension_for_oid(
            x509.ObjectIdentifier("1.2.3.4")
        )
        assert ext.value.value == b"\n\x01\x00"

    def test_unsupported_reason(self, backend):
        crl = _load_cert(
            os.path.join(
                "x509", "custom", "crl_unsupported_reason.pem"
            ),
            x509.load_pem_x509_crl,
            backend
        )

        with pytest.raises(ValueError):
            crl[0].extensions

    def test_invalid_cert_issuer_ext(self, backend):
        crl = _load_cert(
            os.path.join(
                "x509", "custom", "crl_inval_cert_issuer_entry_ext.pem"
            ),
            x509.load_pem_x509_crl,
            backend
        )

        with pytest.raises(ValueError):
            crl[0].extensions

    def test_indexing(self, backend):
        crl = _load_cert(
            os.path.join("x509", "custom", "crl_all_reasons.pem"),
            x509.load_pem_x509_crl,
            backend
        )

        with pytest.raises(IndexError):
            crl[-13]
        with pytest.raises(IndexError):
            crl[12]

        assert crl[-1].serial_number == crl[11].serial_number
        assert len(crl[2:4]) == 2
        assert crl[2:4][0].serial_number == crl[2].serial_number
        assert crl[2:4][1].serial_number == crl[3].serial_number


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestRSACertificate(object):
    def test_load_pem_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert isinstance(cert, x509.Certificate)
        assert cert.serial_number == 11559813051657483483
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1()))
        assert fingerprint == b"2b619ed04bfc9c3b08eb677d272192286a0947a8"
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA1)
        assert (
            cert.signature_algorithm_oid == SignatureAlgorithmOID.RSA_WITH_SHA1
        )

    def test_alternate_rsa_with_sha1_oid(self, backend):
        cert = _load_cert(
            os.path.join("x509", "alternate-rsa-sha1-oid.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA1)
        assert (
            cert.signature_algorithm_oid ==
            SignatureAlgorithmOID._RSA_WITH_SHA1
        )

    def test_cert_serial_number(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )

        with pytest.deprecated_call():
            assert cert.serial == 2
            assert cert.serial_number == 2

    def test_cert_serial_warning(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )

        with pytest.deprecated_call():
            cert.serial

    def test_load_der_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )
        assert isinstance(cert, x509.Certificate)
        assert cert.serial_number == 2
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1()))
        assert fingerprint == b"6f49779533d565e8b7c1062503eab41492c38e4d"
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)

    def test_signature(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert.signature == binascii.unhexlify(
            b"8e0f72fcbebe4755abcaf76c8ce0bae17cde4db16291638e1b1ce04a93cdb4c"
            b"44a3486070986c5a880c14fdf8497e7d289b2630ccb21d24a3d1aa1b2d87482"
            b"07f3a1e16ccdf8daa8a7ea1a33d49774f513edf09270bd8e665b6300a10f003"
            b"66a59076905eb63cf10a81a0ca78a6ef3127f6cb2f6fb7f947fce22a30d8004"
            b"8c243ba2c1a54c425fe12310e8a737638f4920354d4cce25cbd9dea25e6a2fe"
            b"0d8579a5c8d929b9275be221975479f3f75075bcacf09526523b5fd67f7683f"
            b"3cda420fabb1e9e6fc26bc0649cf61bb051d6932fac37066bb16f55903dfe78"
            b"53dc5e505e2a10fbba4f9e93a0d3b53b7fa34b05d7ba6eef869bfc34b8e514f"
            b"d5419f75"
        )
        assert len(cert.signature) == cert.public_key().key_size // 8

    def test_tbs_certificate_bytes(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert.tbs_certificate_bytes == binascii.unhexlify(
            b"308202d8a003020102020900a06cb4b955f7f4db300d06092a864886f70d010"
            b"10505003058310b3009060355040613024155311330110603550408130a536f"
            b"6d652d53746174653121301f060355040a1318496e7465726e6574205769646"
            b"769747320507479204c74643111300f0603550403130848656c6c6f20434130"
            b"1e170d3134313132363231343132305a170d3134313232363231343132305a3"
            b"058310b3009060355040613024155311330110603550408130a536f6d652d53"
            b"746174653121301f060355040a1318496e7465726e657420576964676974732"
            b"0507479204c74643111300f0603550403130848656c6c6f2043413082012230"
            b"0d06092a864886f70d01010105000382010f003082010a0282010100b03af70"
            b"2059e27f1e2284b56bbb26c039153bf81f295b73a49132990645ede4d2da0a9"
            b"13c42e7d38d3589a00d3940d194f6e6d877c2ef812da22a275e83d8be786467"
            b"48b4e7f23d10e873fd72f57a13dec732fc56ab138b1bb308399bb412cd73921"
            b"4ef714e1976e09603405e2556299a05522510ac4574db5e9cb2cf5f99e8f48c"
            b"1696ab3ea2d6d2ddab7d4e1b317188b76a572977f6ece0a4ad396f0150e7d8b"
            b"1a9986c0cb90527ec26ca56e2914c270d2a198b632fa8a2fda55079d3d39864"
            b"b6fb96ddbe331cacb3cb8783a8494ccccd886a3525078847ca01ca5f803e892"
            b"14403e8a4b5499539c0b86f7a0daa45b204a8e079d8a5b03db7ba1ba3d7011a"
            b"70203010001a381bc3081b9301d0603551d0e04160414d8e89dc777e4472656"
            b"f1864695a9f66b7b0400ae3081890603551d23048181307f8014d8e89dc777e"
            b"4472656f1864695a9f66b7b0400aea15ca45a3058310b300906035504061302"
            b"4155311330110603550408130a536f6d652d53746174653121301f060355040"
            b"a1318496e7465726e6574205769646769747320507479204c74643111300f06"
            b"03550403130848656c6c6f204341820900a06cb4b955f7f4db300c0603551d1"
            b"3040530030101ff"
        )
        verifier = cert.public_key().verifier(
            cert.signature, padding.PKCS1v15(), cert.signature_hash_algorithm
        )
        verifier.update(cert.tbs_certificate_bytes)
        verifier.verify()

    def test_issuer(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "Validpre2000UTCnotBeforeDateTest3EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )
        issuer = cert.issuer
        assert isinstance(issuer, x509.Name)
        assert list(issuer) == [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, u'Test Certificates 2011'
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, u'Good CA')
        ]
        assert issuer.get_attributes_for_oid(NameOID.COMMON_NAME) == [
            x509.NameAttribute(NameOID.COMMON_NAME, u'Good CA')
        ]

    def test_all_issuer_name_types(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom",
                "all_supported_names.pem"
            ),
            x509.load_pem_x509_certificate,
            backend
        )
        issuer = cert.issuer

        assert isinstance(issuer, x509.Name)
        assert list(issuer) == [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'CA'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Illinois'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Chicago'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Zero, LLC'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'One, LLC'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'common name 0'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'common name 1'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'OU 0'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'OU 1'),
            x509.NameAttribute(NameOID.DN_QUALIFIER, u'dnQualifier0'),
            x509.NameAttribute(NameOID.DN_QUALIFIER, u'dnQualifier1'),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, u'123'),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, u'456'),
            x509.NameAttribute(NameOID.TITLE, u'Title 0'),
            x509.NameAttribute(NameOID.TITLE, u'Title 1'),
            x509.NameAttribute(NameOID.SURNAME, u'Surname 0'),
            x509.NameAttribute(NameOID.SURNAME, u'Surname 1'),
            x509.NameAttribute(NameOID.GIVEN_NAME, u'Given Name 0'),
            x509.NameAttribute(NameOID.GIVEN_NAME, u'Given Name 1'),
            x509.NameAttribute(NameOID.PSEUDONYM, u'Incognito 0'),
            x509.NameAttribute(NameOID.PSEUDONYM, u'Incognito 1'),
            x509.NameAttribute(NameOID.GENERATION_QUALIFIER, u'Last Gen'),
            x509.NameAttribute(NameOID.GENERATION_QUALIFIER, u'Next Gen'),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'dc0'),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'dc1'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'test0@test.local'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'test1@test.local'),
        ]

    def test_subject(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "Validpre2000UTCnotBeforeDateTest3EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )
        subject = cert.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, u'Test Certificates 2011'
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                u'Valid pre2000 UTC notBefore Date EE Certificate Test3'
            )
        ]
        assert subject.get_attributes_for_oid(NameOID.COMMON_NAME) == [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                u'Valid pre2000 UTC notBefore Date EE Certificate Test3'
            )
        ]

    def test_unicode_name(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom",
                "utf8_common_name.pem"
            ),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) == [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                u'We heart UTF8!\u2122'
            )
        ]
        assert cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME) == [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                u'We heart UTF8!\u2122'
            )
        ]

    def test_non_ascii_dns_name(self, backend):
        cert = _load_cert(
            os.path.join("x509", "utf8-dnsname.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value

        names = san.get_values_for_type(x509.DNSName)

        assert names == [
            u'partner.biztositas.hu', u'biztositas.hu', u'*.biztositas.hu',
            u'biztos\xedt\xe1s.hu', u'*.biztos\xedt\xe1s.hu',
            u'xn--biztosts-fza2j.hu', u'*.xn--biztosts-fza2j.hu'
        ]

    def test_all_subject_name_types(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom",
                "all_supported_names.pem"
            ),
            x509.load_pem_x509_certificate,
            backend
        )
        subject = cert.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'AU'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'DE'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'New York'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Ithaca'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Org Zero, LLC'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Org One, LLC'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'CN 0'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'CN 1'),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, u'Engineering 0'
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, u'Engineering 1'
            ),
            x509.NameAttribute(NameOID.DN_QUALIFIER, u'qualified0'),
            x509.NameAttribute(NameOID.DN_QUALIFIER, u'qualified1'),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, u'789'),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, u'012'),
            x509.NameAttribute(NameOID.TITLE, u'Title IX'),
            x509.NameAttribute(NameOID.TITLE, u'Title X'),
            x509.NameAttribute(NameOID.SURNAME, u'Last 0'),
            x509.NameAttribute(NameOID.SURNAME, u'Last 1'),
            x509.NameAttribute(NameOID.GIVEN_NAME, u'First 0'),
            x509.NameAttribute(NameOID.GIVEN_NAME, u'First 1'),
            x509.NameAttribute(NameOID.PSEUDONYM, u'Guy Incognito 0'),
            x509.NameAttribute(NameOID.PSEUDONYM, u'Guy Incognito 1'),
            x509.NameAttribute(NameOID.GENERATION_QUALIFIER, u'32X'),
            x509.NameAttribute(NameOID.GENERATION_QUALIFIER, u'Dreamcast'),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'dc2'),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'dc3'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'test2@test.local'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'test3@test.local'),
        ]

    def test_load_good_ca_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )

        assert cert.not_valid_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_valid_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.serial_number == 2
        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert cert.version is x509.Version.v3
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1()))
        assert fingerprint == b"6f49779533d565e8b7c1062503eab41492c38e4d"

    def test_utc_pre_2000_not_before_cert(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "Validpre2000UTCnotBeforeDateTest3EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )

        assert cert.not_valid_before == datetime.datetime(1950, 1, 1, 12, 1)

    def test_pre_2000_utc_not_after_cert(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "Invalidpre2000UTCEEnotAfterDateTest7EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )

        assert cert.not_valid_after == datetime.datetime(1999, 1, 1, 12, 1)

    def test_post_2000_utc_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert.not_valid_before == datetime.datetime(
            2014, 11, 26, 21, 41, 20
        )
        assert cert.not_valid_after == datetime.datetime(
            2014, 12, 26, 21, 41, 20
        )

    def test_generalized_time_not_before_cert(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "ValidGeneralizedTimenotBeforeDateTest4EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )
        assert cert.not_valid_before == datetime.datetime(2002, 1, 1, 12, 1)
        assert cert.not_valid_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.version is x509.Version.v3

    def test_generalized_time_not_after_cert(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "ValidGeneralizedTimenotAfterDateTest8EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )
        assert cert.not_valid_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_valid_after == datetime.datetime(2050, 1, 1, 12, 1)
        assert cert.version is x509.Version.v3

    def test_invalid_version_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "invalid_version.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        with pytest.raises(x509.InvalidVersion) as exc:
            cert.version

        assert exc.value.parsed_version == 7

    def test_eq(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        cert2 = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert == cert2

    def test_ne(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        cert2 = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "ValidGeneralizedTimenotAfterDateTest8EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )
        assert cert != cert2
        assert cert != object()

    def test_hash(self, backend):
        cert1 = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        cert2 = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        cert3 = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "ValidGeneralizedTimenotAfterDateTest8EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )

        assert hash(cert1) == hash(cert2)
        assert hash(cert1) != hash(cert3)

    def test_version_1_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "v1_cert.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert.version is x509.Version.v1

    def test_invalid_pem(self, backend):
        with pytest.raises(ValueError):
            x509.load_pem_x509_certificate(b"notacert", backend)

    def test_invalid_der(self, backend):
        with pytest.raises(ValueError):
            x509.load_der_x509_certificate(b"notacert", backend)

    def test_unsupported_signature_hash_algorithm_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "verisign_md2_root.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        with pytest.raises(UnsupportedAlgorithm):
            cert.signature_hash_algorithm

    def test_public_bytes_pem(self, backend):
        # Load an existing certificate.
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )

        # Encode it to PEM and load it back.
        cert = x509.load_pem_x509_certificate(cert.public_bytes(
            encoding=serialization.Encoding.PEM,
        ), backend)

        # We should recover what we had to start with.
        assert cert.not_valid_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_valid_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.serial_number == 2
        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert cert.version is x509.Version.v3
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1()))
        assert fingerprint == b"6f49779533d565e8b7c1062503eab41492c38e4d"

    def test_public_bytes_der(self, backend):
        # Load an existing certificate.
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )

        # Encode it to DER and load it back.
        cert = x509.load_der_x509_certificate(cert.public_bytes(
            encoding=serialization.Encoding.DER,
        ), backend)

        # We should recover what we had to start with.
        assert cert.not_valid_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_valid_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.serial_number == 2
        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert cert.version is x509.Version.v3
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1()))
        assert fingerprint == b"6f49779533d565e8b7c1062503eab41492c38e4d"

    def test_public_bytes_invalid_encoding(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )

        with pytest.raises(TypeError):
            cert.public_bytes('NotAnEncoding')

    @pytest.mark.parametrize(
        ("cert_path", "loader_func", "encoding"),
        [
            (
                os.path.join("x509", "v1_cert.pem"),
                x509.load_pem_x509_certificate,
                serialization.Encoding.PEM,
            ),
            (
                os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
                x509.load_der_x509_certificate,
                serialization.Encoding.DER,
            ),
        ]
    )
    def test_public_bytes_match(self, cert_path, loader_func, encoding,
                                backend):
        cert_bytes = load_vectors_from_file(
            cert_path, lambda pemfile: pemfile.read(), mode="rb"
        )
        cert = loader_func(cert_bytes, backend)
        serialized = cert.public_bytes(encoding)
        assert serialized == cert_bytes

    def test_certificate_repr(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "cryptography.io.pem"
            ),
            x509.load_pem_x509_certificate,
            backend
        )
        if six.PY3:
            assert repr(cert) == (
                "<Certificate(subject=<Name([<NameAttribute(oid=<ObjectIdentif"
                "ier(oid=2.5.4.11, name=organizationalUnitName)>, value='GT487"
                "42965')>, <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.11, "
                "name=organizationalUnitName)>, value='See www.rapidssl.com/re"
                "sources/cps (c)14')>, <NameAttribute(oid=<ObjectIdentifier(oi"
                "d=2.5.4.11, name=organizationalUnitName)>, value='Domain Cont"
                "rol Validated - RapidSSL(R)')>, <NameAttribute(oid=<ObjectIde"
                "ntifier(oid=2.5.4.3, name=commonName)>, value='www.cryptograp"
                "hy.io')>])>, ...)>"
            )
        else:
            assert repr(cert) == (
                "<Certificate(subject=<Name([<NameAttribute(oid=<ObjectIdentif"
                "ier(oid=2.5.4.11, name=organizationalUnitName)>, value=u'GT48"
                "742965')>, <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.11,"
                " name=organizationalUnitName)>, value=u'See www.rapidssl.com/"
                "resources/cps (c)14')>, <NameAttribute(oid=<ObjectIdentifier("
                "oid=2.5.4.11, name=organizationalUnitName)>, value=u'Domain C"
                "ontrol Validated - RapidSSL(R)')>, <NameAttribute(oid=<Object"
                "Identifier(oid=2.5.4.3, name=commonName)>, value=u'www.crypto"
                "graphy.io')>])>, ...)>"
            )

    def test_parse_tls_feature_extension(self, backend):
        cert = _load_cert(
            os.path.join("x509", "tls-feature-ocsp-staple.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        ext = cert.extensions.get_extension_for_class(x509.TLSFeature)
        assert ext.critical is False
        assert ext.value == x509.TLSFeature(
            [x509.TLSFeatureType.status_request]
        )


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestRSACertificateRequest(object):
    @pytest.mark.parametrize(
        ("path", "loader_func"),
        [
            [
                os.path.join("x509", "requests", "rsa_sha1.pem"),
                x509.load_pem_x509_csr
            ],
            [
                os.path.join("x509", "requests", "rsa_sha1.der"),
                x509.load_der_x509_csr
            ],
        ]
    )
    def test_load_rsa_certificate_request(self, path, loader_func, backend):
        request = _load_cert(path, loader_func, backend)
        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        assert (
            request.signature_algorithm_oid ==
            SignatureAlgorithmOID.RSA_WITH_SHA1
        )
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ]
        extensions = request.extensions
        assert isinstance(extensions, x509.Extensions)
        assert list(extensions) == []

    @pytest.mark.parametrize(
        "loader_func",
        [x509.load_pem_x509_csr, x509.load_der_x509_csr]
    )
    def test_invalid_certificate_request(self, loader_func, backend):
        with pytest.raises(ValueError):
            loader_func(b"notacsr", backend)

    def test_unsupported_signature_hash_algorithm_request(self, backend):
        request = _load_cert(
            os.path.join("x509", "requests", "rsa_md4.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        with pytest.raises(UnsupportedAlgorithm):
            request.signature_hash_algorithm

    def test_duplicate_extension(self, backend):
        request = _load_cert(
            os.path.join(
                "x509", "requests", "two_basic_constraints.pem"
            ),
            x509.load_pem_x509_csr,
            backend
        )
        with pytest.raises(x509.DuplicateExtension) as exc:
            request.extensions

        assert exc.value.oid == ExtensionOID.BASIC_CONSTRAINTS

    def test_unsupported_critical_extension(self, backend):
        request = _load_cert(
            os.path.join(
                "x509", "requests", "unsupported_extension_critical.pem"
            ),
            x509.load_pem_x509_csr,
            backend
        )
        ext = request.extensions.get_extension_for_oid(
            x509.ObjectIdentifier('1.2.3.4')
        )
        assert ext.value.value == b"value"

    def test_unsupported_extension(self, backend):
        request = _load_cert(
            os.path.join(
                "x509", "requests", "unsupported_extension.pem"
            ),
            x509.load_pem_x509_csr,
            backend
        )
        extensions = request.extensions
        assert len(extensions) == 1
        assert extensions[0].oid == x509.ObjectIdentifier("1.2.3.4")
        assert extensions[0].value == x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.2.3.4"), b"value"
        )

    def test_request_basic_constraints(self, backend):
        request = _load_cert(
            os.path.join(
                "x509", "requests", "basic_constraints.pem"
            ),
            x509.load_pem_x509_csr,
            backend
        )
        extensions = request.extensions
        assert isinstance(extensions, x509.Extensions)
        assert list(extensions) == [
            x509.Extension(
                ExtensionOID.BASIC_CONSTRAINTS,
                True,
                x509.BasicConstraints(ca=True, path_length=1),
            ),
        ]

    def test_subject_alt_name(self, backend):
        request = _load_cert(
            os.path.join("x509", "requests", "san_rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend,
        )
        ext = request.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert list(ext.value) == [
            x509.DNSName(u"cryptography.io"),
            x509.DNSName(u"sub.cryptography.io"),
        ]

    def test_public_bytes_pem(self, backend):
        # Load an existing CSR.
        request = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )

        # Encode it to PEM and load it back.
        request = x509.load_pem_x509_csr(request.public_bytes(
            encoding=serialization.Encoding.PEM,
        ), backend)

        # We should recover what we had to start with.
        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ]

    def test_public_bytes_der(self, backend):
        # Load an existing CSR.
        request = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )

        # Encode it to DER and load it back.
        request = x509.load_der_x509_csr(request.public_bytes(
            encoding=serialization.Encoding.DER,
        ), backend)

        # We should recover what we had to start with.
        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ]

    def test_signature(self, backend):
        request = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        assert request.signature == binascii.unhexlify(
            b"8364c86ffbbfe0bfc9a21f831256658ca8989741b80576d36f08a934603a43b1"
            b"837246d00167a518abb1de7b51a1e5b7ebea14944800818b1a923c804f120a0d"
            b"624f6310ef79e8612755c2b01dcc7f59dfdbce0db3f2630f185f504b8c17af80"
            b"cbd364fa5fda68337153930948226cd4638287a0aed6524d3006885c19028a1e"
            b"e2f5a91d6e77dbaa0b49996ee0a0c60b55b61bd080a08bb34aa7f3e07e91f37f"
            b"6a11645be2d8654c1570dcda145ed7cc92017f7d53225d7f283f3459ec5bda41"
            b"cf6dd75d43676c543483385226b7e4fa29c8739f1b0eaf199613593991979862"
            b"e36181e8c4c270c354b7f52c128db1b70639823324c7ea24791b7bc3d7005f3b"
        )

    def test_tbs_certrequest_bytes(self, backend):
        request = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        assert request.tbs_certrequest_bytes == binascii.unhexlify(
            b"308201840201003057310b3009060355040613025553310e300c060355040813"
            b"055465786173310f300d0603550407130641757374696e310d300b060355040a"
            b"130450794341311830160603550403130f63727970746f6772617068792e696f"
            b"30820122300d06092a864886f70d01010105000382010f003082010a02820101"
            b"00a840a78460cb861066dfa3045a94ba6cf1b7ab9d24c761cffddcc2cb5e3f1d"
            b"c3e4be253e7039ef14fe9d6d2304f50d9f2e1584c51530ab75086f357138bff7"
            b"b854d067d1d5f384f1f2f2c39cc3b15415e2638554ef8402648ae3ef08336f22"
            b"b7ecc6d4331c2b21c3091a7f7a9518180754a646640b60419e4cc6f5c798110a"
            b"7f030a639fe87e33b4776dfcd993940ec776ab57a181ad8598857976dc303f9a"
            b"573ca619ab3fe596328e92806b828683edc17cc256b41948a2bfa8d047d2158d"
            b"3d8e069aa05fa85b3272abb1c4b4422b6366f3b70e642377b145cd6259e5d3e7"
            b"db048d51921e50766a37b1b130ee6b11f507d20a834001e8de16a92c14f2e964"
            b"a30203010001a000"
        )
        verifier = request.public_key().verifier(
            request.signature,
            padding.PKCS1v15(),
            request.signature_hash_algorithm
        )
        verifier.update(request.tbs_certrequest_bytes)
        verifier.verify()

    def test_public_bytes_invalid_encoding(self, backend):
        request = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )

        with pytest.raises(TypeError):
            request.public_bytes('NotAnEncoding')

    def test_signature_invalid(self, backend):
        request = _load_cert(
            os.path.join("x509", "requests", "invalid_signature.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        assert not request.is_signature_valid

    def test_signature_valid(self, backend):
        request = _load_cert(
            os.path.join("x509", "requests", "rsa_sha256.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        assert request.is_signature_valid

    @pytest.mark.parametrize(
        ("request_path", "loader_func", "encoding"),
        [
            (
                os.path.join("x509", "requests", "rsa_sha1.pem"),
                x509.load_pem_x509_csr,
                serialization.Encoding.PEM,
            ),
            (
                os.path.join("x509", "requests", "rsa_sha1.der"),
                x509.load_der_x509_csr,
                serialization.Encoding.DER,
            ),
        ]
    )
    def test_public_bytes_match(self, request_path, loader_func, encoding,
                                backend):
        request_bytes = load_vectors_from_file(
            request_path, lambda pemfile: pemfile.read(), mode="rb"
        )
        request = loader_func(request_bytes, backend)
        serialized = request.public_bytes(encoding)
        assert serialized == request_bytes

    def test_eq(self, backend):
        request1 = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        request2 = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )

        assert request1 == request2

    def test_ne(self, backend):
        request1 = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        request2 = _load_cert(
            os.path.join("x509", "requests", "san_rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )

        assert request1 != request2
        assert request1 != object()

    def test_hash(self, backend):
        request1 = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        request2 = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        request3 = _load_cert(
            os.path.join("x509", "requests", "san_rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )

        assert hash(request1) == hash(request2)
        assert hash(request1) != hash(request3)

    def test_build_cert(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), True,
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"cryptography.io")]),
            critical=False,
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA1(), backend)

        assert cert.version is x509.Version.v3
        assert cert.not_valid_before == not_valid_before
        assert cert.not_valid_after == not_valid_after
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is False
        assert basic_constraints.value.path_length is None
        subject_alternative_name = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert list(subject_alternative_name.value) == [
            x509.DNSName(u"cryptography.io"),
        ]

    def test_build_cert_private_type_encoding(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)
        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)
        name = x509.Name([
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, u'Texas',
                _ASN1Type.PrintableString),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(
                NameOID.COMMON_NAME, u'cryptography.io', _ASN1Type.IA5String),
        ])
        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(
            name
        ).subject_name(
            name
        ).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(not_valid_after)
        cert = builder.sign(issuer_private_key, hashes.SHA256(), backend)

        for dn in (cert.subject, cert.issuer):
            assert dn.get_attributes_for_oid(
                NameOID.STATE_OR_PROVINCE_NAME
            )[0]._type == _ASN1Type.PrintableString
            assert dn.get_attributes_for_oid(
                NameOID.STATE_OR_PROVINCE_NAME
            )[0]._type == _ASN1Type.PrintableString
            assert dn.get_attributes_for_oid(
                NameOID.LOCALITY_NAME
            )[0]._type == _ASN1Type.UTF8String

    def test_build_cert_printable_string_country_name(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.JURISDICTION_COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.JURISDICTION_COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA256(), backend)

        parsed = Certificate.load(
            cert.public_bytes(serialization.Encoding.DER))

        # Check that each value was encoded as an ASN.1 PRINTABLESTRING.
        assert parsed.subject.chosen[0][0]['value'].chosen.tag == 19
        assert parsed.issuer.chosen[0][0]['value'].chosen.tag == 19
        if (
            # This only works correctly in OpenSSL 1.1.0f+ and 1.0.2l+
            backend._lib.CRYPTOGRAPHY_OPENSSL_110F_OR_GREATER or (
                backend._lib.CRYPTOGRAPHY_OPENSSL_102L_OR_GREATER and
                not backend._lib.CRYPTOGRAPHY_OPENSSL_110_OR_GREATER
            )
        ):
            assert parsed.subject.chosen[1][0]['value'].chosen.tag == 19
            assert parsed.issuer.chosen[1][0]['value'].chosen.tag == 19


class TestCertificateBuilder(object):
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_checks_for_unsupported_extensions(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            private_key.public_key()
        ).serial_number(
            777
        ).not_valid_before(
            datetime.datetime(1999, 1, 1)
        ).not_valid_after(
            datetime.datetime(2020, 1, 1)
        ).add_extension(
            DummyExtension(), False
        )

        with pytest.raises(NotImplementedError):
            builder.sign(private_key, hashes.SHA1(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_encode_nonstandard_aia(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        aia = x509.AuthorityInformationAccess([
            x509.AccessDescription(
                x509.ObjectIdentifier("2.999.7"),
                x509.UniformResourceIdentifier(u"http://example.com")
            ),
        ])

        builder = x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            private_key.public_key()
        ).serial_number(
            777
        ).not_valid_before(
            datetime.datetime(1999, 1, 1)
        ).not_valid_after(
            datetime.datetime(2020, 1, 1)
        ).add_extension(
            aia, False
        )

        builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.skipif(sys.platform != "win32", reason="Requires windows")
    @pytest.mark.parametrize(
        ("not_valid_before", "not_valid_after"),
        [
            [datetime.datetime(1999, 1, 1), datetime.datetime(9999, 1, 1)],
            [datetime.datetime(9999, 1, 1), datetime.datetime(9999, 12, 31)],
        ]
    )
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_invalid_time_windows(self, not_valid_before, not_valid_after,
                                  backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            private_key.public_key()
        ).serial_number(
            777
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_subject_name(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )
        with pytest.raises(ValueError):
            builder.sign(subject_private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_issuer_name(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().serial_number(
            777
        ).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )
        with pytest.raises(ValueError):
            builder.sign(subject_private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_public_key(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )
        with pytest.raises(ValueError):
            builder.sign(subject_private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_not_valid_before(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )
        with pytest.raises(ValueError):
            builder.sign(subject_private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_not_valid_after(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.sign(subject_private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_serial_number(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )
        with pytest.raises(ValueError):
            builder.sign(subject_private_key, hashes.SHA256(), backend)

    def test_issuer_name_must_be_a_name_type(self):
        builder = x509.CertificateBuilder()

        with pytest.raises(TypeError):
            builder.issuer_name("subject")

        with pytest.raises(TypeError):
            builder.issuer_name(object)

    def test_issuer_name_may_only_be_set_once(self):
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])
        builder = x509.CertificateBuilder().issuer_name(name)

        with pytest.raises(ValueError):
            builder.issuer_name(name)

    def test_subject_name_must_be_a_name_type(self):
        builder = x509.CertificateBuilder()

        with pytest.raises(TypeError):
            builder.subject_name("subject")

        with pytest.raises(TypeError):
            builder.subject_name(object)

    def test_subject_name_may_only_be_set_once(self):
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])
        builder = x509.CertificateBuilder().subject_name(name)

        with pytest.raises(ValueError):
            builder.subject_name(name)

    def test_not_valid_before_after_not_valid_after(self):
        builder = x509.CertificateBuilder()

        builder = builder.not_valid_after(
            datetime.datetime(2002, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.not_valid_before(
                datetime.datetime(2003, 1, 1, 12, 1)
            )

    def test_not_valid_after_before_not_valid_before(self):
        builder = x509.CertificateBuilder()

        builder = builder.not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.not_valid_after(
                datetime.datetime(2001, 1, 1, 12, 1)
            )

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_public_key_must_be_public_key(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder()

        with pytest.raises(TypeError):
            builder.public_key(private_key)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_public_key_may_only_be_set_once(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder().public_key(public_key)

        with pytest.raises(ValueError):
            builder.public_key(public_key)

    def test_serial_number_must_be_an_integer_type(self):
        with pytest.raises(TypeError):
            x509.CertificateBuilder().serial_number(10.0)

    def test_serial_number_must_be_non_negative(self):
        with pytest.raises(ValueError):
            x509.CertificateBuilder().serial_number(-1)

    def test_serial_number_must_be_positive(self):
        with pytest.raises(ValueError):
            x509.CertificateBuilder().serial_number(0)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_minimal_serial_number(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().serial_number(
            1
        ).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'RU'),
        ])).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'RU'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )
        cert = builder.sign(subject_private_key, hashes.SHA256(), backend)
        assert cert.serial_number == 1

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_biggest_serial_number(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().serial_number(
            (1 << 159) - 1
        ).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'RU'),
        ])).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'RU'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )
        cert = builder.sign(subject_private_key, hashes.SHA256(), backend)
        assert cert.serial_number == (1 << 159) - 1

    def test_serial_number_must_be_less_than_160_bits_long(self):
        with pytest.raises(ValueError):
            x509.CertificateBuilder().serial_number(1 << 159)

    def test_serial_number_may_only_be_set_once(self):
        builder = x509.CertificateBuilder().serial_number(10)

        with pytest.raises(ValueError):
            builder.serial_number(20)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_aware_not_valid_after(self, backend):
        time = datetime.datetime(2012, 1, 16, 22, 43)
        tz = pytz.timezone("US/Pacific")
        time = tz.localize(time)
        utc_time = datetime.datetime(2012, 1, 17, 6, 43)
        private_key = RSA_KEY_2048.private_key(backend)
        cert_builder = x509.CertificateBuilder().not_valid_after(time)
        cert_builder = cert_builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).serial_number(
            1
        ).public_key(
            private_key.public_key()
        ).not_valid_before(
            utc_time - datetime.timedelta(days=365)
        )

        cert = cert_builder.sign(private_key, hashes.SHA256(), backend)
        assert cert.not_valid_after == utc_time

    def test_invalid_not_valid_after(self):
        with pytest.raises(TypeError):
            x509.CertificateBuilder().not_valid_after(104204304504)

        with pytest.raises(TypeError):
            x509.CertificateBuilder().not_valid_after(datetime.time())

        with pytest.raises(ValueError):
            x509.CertificateBuilder().not_valid_after(
                datetime.datetime(1960, 8, 10)
            )

    def test_not_valid_after_may_only_be_set_once(self):
        builder = x509.CertificateBuilder().not_valid_after(
            datetime.datetime.now()
        )

        with pytest.raises(ValueError):
            builder.not_valid_after(
                datetime.datetime.now()
            )

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_aware_not_valid_before(self, backend):
        time = datetime.datetime(2012, 1, 16, 22, 43)
        tz = pytz.timezone("US/Pacific")
        time = tz.localize(time)
        utc_time = datetime.datetime(2012, 1, 17, 6, 43)
        private_key = RSA_KEY_2048.private_key(backend)
        cert_builder = x509.CertificateBuilder().not_valid_before(time)
        cert_builder = cert_builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).serial_number(
            1
        ).public_key(
            private_key.public_key()
        ).not_valid_after(
            utc_time + datetime.timedelta(days=366)
        )

        cert = cert_builder.sign(private_key, hashes.SHA256(), backend)
        assert cert.not_valid_before == utc_time

    def test_invalid_not_valid_before(self):
        with pytest.raises(TypeError):
            x509.CertificateBuilder().not_valid_before(104204304504)

        with pytest.raises(TypeError):
            x509.CertificateBuilder().not_valid_before(datetime.time())

        with pytest.raises(ValueError):
            x509.CertificateBuilder().not_valid_before(
                datetime.datetime(1960, 8, 10)
            )

    def test_not_valid_before_may_only_be_set_once(self):
        builder = x509.CertificateBuilder().not_valid_before(
            datetime.datetime.now()
        )

        with pytest.raises(ValueError):
            builder.not_valid_before(
                datetime.datetime.now()
            )

    def test_add_extension_checks_for_duplicates(self):
        builder = x509.CertificateBuilder().add_extension(
            x509.BasicConstraints(ca=False, path_length=None), True,
        )

        with pytest.raises(ValueError):
            builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), True,
            )

    def test_add_invalid_extension_type(self):
        builder = x509.CertificateBuilder()

        with pytest.raises(TypeError):
            builder.add_extension(object(), False)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_with_unsupported_hash(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).serial_number(
            1
        ).public_key(
            private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2032, 1, 1, 12, 1)
        )

        with pytest.raises(TypeError):
            builder.sign(private_key, object(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_rsa_with_md5(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).serial_number(
            1
        ).public_key(
            private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2032, 1, 1, 12, 1)
        )
        cert = builder.sign(private_key, hashes.MD5(), backend)
        assert isinstance(cert.signature_hash_algorithm, hashes.MD5)

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_dsa_with_md5(self, backend):
        private_key = DSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).serial_number(
            1
        ).public_key(
            private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2032, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.MD5(), backend)

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_ec_with_md5(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        private_key = EC_KEY_SECP256R1.private_key(backend)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).serial_number(
            1
        ).public_key(
            private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2032, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.MD5(), backend)

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_cert_with_dsa_private_key(self, backend):
        issuer_private_key = DSA_KEY_2048.private_key(backend)
        subject_private_key = DSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), True,
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"cryptography.io")]),
            critical=False,
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA1(), backend)

        assert cert.version is x509.Version.v3
        assert cert.not_valid_before == not_valid_before
        assert cert.not_valid_after == not_valid_after
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is False
        assert basic_constraints.value.path_length is None
        subject_alternative_name = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert list(subject_alternative_name.value) == [
            x509.DNSName(u"cryptography.io"),
        ]

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_cert_with_ec_private_key(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        issuer_private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        subject_private_key = ec.generate_private_key(ec.SECP256R1(), backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), True,
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"cryptography.io")]),
            critical=False,
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA1(), backend)

        assert cert.version is x509.Version.v3
        assert cert.not_valid_before == not_valid_before
        assert cert.not_valid_after == not_valid_after
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is False
        assert basic_constraints.value.path_length is None
        subject_alternative_name = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert list(subject_alternative_name.value) == [
            x509.DNSName(u"cryptography.io"),
        ]

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_cert_with_rsa_key_too_small(self, backend):
        issuer_private_key = RSA_KEY_512.private_key(backend)
        subject_private_key = RSA_KEY_512.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        with pytest.raises(ValueError):
            builder.sign(issuer_private_key, hashes.SHA512(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    @pytest.mark.parametrize(
        "add_ext",
        [
            x509.SubjectAlternativeName(
                [
                    # These examples exist to verify compatibility with
                    # certificates that have utf8 encoded data in the ia5string
                    x509.DNSName._init_without_validation(u'a\xedt\xe1s.test'),
                    x509.RFC822Name._init_without_validation(
                        u'test@a\xedt\xe1s.test'
                    ),
                    x509.UniformResourceIdentifier._init_without_validation(
                        u'http://a\xedt\xe1s.test'
                    ),
                ]
            ),
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.16.840.1.12345.1.2.3.4.1"),
                    [u"http://other.com/cps"]
                )
            ]),
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.16.840.1.12345.1.2.3.4.1"),
                    None
                )
            ]),
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.16.840.1.12345.1.2.3.4.1"),
                    [
                        u"http://example.com/cps",
                        u"http://other.com/cps",
                        x509.UserNotice(
                            x509.NoticeReference(u"my org", [1, 2, 3, 4]),
                            u"thing"
                        )
                    ]
                )
            ]),
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.16.840.1.12345.1.2.3.4.1"),
                    [
                        u"http://example.com/cps",
                        x509.UserNotice(
                            x509.NoticeReference(u"UTF8\u2122'", [1, 2, 3, 4]),
                            u"We heart UTF8!\u2122"
                        )
                    ]
                )
            ]),
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.16.840.1.12345.1.2.3.4.1"),
                    [x509.UserNotice(None, u"thing")]
                )
            ]),
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.16.840.1.12345.1.2.3.4.1"),
                    [
                        x509.UserNotice(
                            x509.NoticeReference(u"my org", [1, 2, 3, 4]),
                            None
                        )
                    ]
                )
            ]),
            x509.IssuerAlternativeName([
                x509.DNSName(u"myissuer"),
                x509.RFC822Name(u"email@domain.com"),
            ]),
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CODE_SIGNING,
            ]),
            x509.InhibitAnyPolicy(3),
            x509.TLSFeature([x509.TLSFeatureType.status_request]),
            x509.TLSFeature([x509.TLSFeatureType.status_request_v2]),
            x509.TLSFeature([
                x509.TLSFeatureType.status_request,
                x509.TLSFeatureType.status_request_v2
            ]),
            x509.NameConstraints(
                permitted_subtrees=[
                    x509.IPAddress(ipaddress.IPv4Network(u"192.168.0.0/24")),
                    x509.IPAddress(ipaddress.IPv4Network(u"192.168.0.0/29")),
                    x509.IPAddress(ipaddress.IPv4Network(u"127.0.0.1/32")),
                    x509.IPAddress(ipaddress.IPv4Network(u"8.0.0.0/8")),
                    x509.IPAddress(ipaddress.IPv4Network(u"0.0.0.0/0")),
                    x509.IPAddress(
                        ipaddress.IPv6Network(u"FF:0:0:0:0:0:0:0/96")
                    ),
                    x509.IPAddress(
                        ipaddress.IPv6Network(u"FF:FF:0:0:0:0:0:0/128")
                    ),
                ],
                excluded_subtrees=[x509.DNSName(u"name.local")]
            ),
            x509.NameConstraints(
                permitted_subtrees=[
                    x509.IPAddress(ipaddress.IPv4Network(u"0.0.0.0/0")),
                ],
                excluded_subtrees=None
            ),
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[x509.DNSName(u"name.local")]
            ),
            x509.PolicyConstraints(
                require_explicit_policy=None,
                inhibit_policy_mapping=1
            ),
            x509.PolicyConstraints(
                require_explicit_policy=3,
                inhibit_policy_mapping=1
            ),
            x509.PolicyConstraints(
                require_explicit_policy=0,
                inhibit_policy_mapping=None
            ),
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=None,
                    relative_name=x509.RelativeDistinguishedName([
                        x509.NameAttribute(
                            NameOID.COMMON_NAME,
                            u"indirect CRL for indirectCRL CA3"
                        ),
                    ]),
                    reasons=None,
                    crl_issuer=[x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                            x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME,
                                u"Test Certificates 2011"
                            ),
                            x509.NameAttribute(
                                NameOID.ORGANIZATIONAL_UNIT_NAME,
                                u"indirectCRL CA3 cRLIssuer"
                            ),
                        ])
                    )],
                )
            ]),
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                        ])
                    )],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=[x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME,
                                u"cryptography Testing"
                            ),
                        ])
                    )],
                )
            ]),
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(
                            u"http://myhost.com/myca.crl"
                        ),
                        x509.UniformResourceIdentifier(
                            u"http://backup.myhost.com/myca.crl"
                        )
                    ],
                    relative_name=None,
                    reasons=frozenset([
                        x509.ReasonFlags.key_compromise,
                        x509.ReasonFlags.ca_compromise
                    ]),
                    crl_issuer=[x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, u"cryptography CA"
                            ),
                        ])
                    )],
                )
            ]),
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        u"http://domain.com/some.crl"
                    )],
                    relative_name=None,
                    reasons=frozenset([
                        x509.ReasonFlags.key_compromise,
                        x509.ReasonFlags.ca_compromise,
                        x509.ReasonFlags.affiliation_changed,
                        x509.ReasonFlags.superseded,
                        x509.ReasonFlags.privilege_withdrawn,
                        x509.ReasonFlags.cessation_of_operation,
                        x509.ReasonFlags.aa_compromise,
                        x509.ReasonFlags.certificate_hold,
                    ]),
                    crl_issuer=None
                )
            ]),
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=None,
                    relative_name=None,
                    reasons=None,
                    crl_issuer=[x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, u"cryptography CA"
                            ),
                        ])
                    )],
                )
            ]),
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        u"http://domain.com/some.crl"
                    )],
                    relative_name=None,
                    reasons=frozenset([x509.ReasonFlags.aa_compromise]),
                    crl_issuer=None
                )
            ]),
            x509.FreshestCRL([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        u"http://domain.com/some.crl"
                    )],
                    relative_name=None,
                    reasons=frozenset([
                        x509.ReasonFlags.key_compromise,
                        x509.ReasonFlags.ca_compromise,
                        x509.ReasonFlags.affiliation_changed,
                        x509.ReasonFlags.superseded,
                        x509.ReasonFlags.privilege_withdrawn,
                        x509.ReasonFlags.cessation_of_operation,
                        x509.ReasonFlags.aa_compromise,
                        x509.ReasonFlags.certificate_hold,
                    ]),
                    crl_issuer=None
                )
            ]),
            x509.FreshestCRL([
                x509.DistributionPoint(
                    full_name=None,
                    relative_name=x509.RelativeDistinguishedName([
                        x509.NameAttribute(
                            NameOID.COMMON_NAME,
                            u"indirect CRL for indirectCRL CA3"
                        ),
                    ]),
                    reasons=None,
                    crl_issuer=None,
                )
            ]),
        ]
    )
    def test_ext(self, add_ext, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).public_key(
            subject_private_key.public_key()
        ).serial_number(
            123
        ).add_extension(
            add_ext, critical=False
        ).sign(issuer_private_key, hashes.SHA256(), backend)

        ext = cert.extensions.get_extension_for_class(type(add_ext))
        assert ext.critical is False
        assert ext.value == add_ext

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_key_usage(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).public_key(
            subject_private_key.public_key()
        ).serial_number(
            123
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=False
        ).sign(issuer_private_key, hashes.SHA256(), backend)

        ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        assert ext.critical is False
        assert ext.value == x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_ca_request_with_path_length_none(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                   u'PyCA'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(private_key, hashes.SHA1(), backend)

        loaded_request = x509.load_pem_x509_csr(
            request.public_bytes(encoding=serialization.Encoding.PEM), backend
        )
        subject = loaded_request.subject
        assert isinstance(subject, x509.Name)
        basic_constraints = request.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.path_length is None

    @pytest.mark.parametrize(
        "unrecognized", [
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.2.3.4.5"),
                b"abcdef",
            )
        ]
    )
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_unrecognized_extension(self, backend, unrecognized):
        private_key = RSA_KEY_2048.private_key(backend)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US')])
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        ).public_key(
            private_key.public_key()
        ).serial_number(
            123
        ).add_extension(
            unrecognized, critical=False
        ).sign(private_key, hashes.SHA256(), backend)

        ext = cert.extensions.get_extension_for_oid(unrecognized.oid)

        assert ext.value == unrecognized


@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestCertificateSigningRequestBuilder(object):
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_sign_invalid_hash_algorithm(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([])
        )
        with pytest.raises(TypeError):
            builder.sign(private_key, 'NotAHash', backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_sign_rsa_with_md5(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            ])
        )
        request = builder.sign(private_key, hashes.MD5(), backend)
        assert isinstance(request.signature_hash_algorithm, hashes.MD5)

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    def test_sign_dsa_with_md5(self, backend):
        private_key = DSA_KEY_2048.private_key(backend)
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            ])
        )
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.MD5(), backend)

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    def test_sign_ec_with_md5(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        private_key = EC_KEY_SECP256R1.private_key(backend)
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            ])
        )
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.MD5(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_no_subject_name(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        builder = x509.CertificateSigningRequestBuilder()
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_build_ca_request_with_rsa(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(private_key, hashes.SHA1(), backend)

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
        ]
        basic_constraints = request.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 2

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_build_ca_request_with_unicode(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                   u'PyCA\U0001f37a'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(private_key, hashes.SHA1(), backend)

        loaded_request = x509.load_pem_x509_csr(
            request.public_bytes(encoding=serialization.Encoding.PEM), backend
        )
        subject = loaded_request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA\U0001f37a'),
        ]

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_build_ca_request_with_multivalue_rdns(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        subject = x509.Name([
            x509.RelativeDistinguishedName([
                x509.NameAttribute(NameOID.TITLE, u'Test'),
                x509.NameAttribute(NameOID.COMMON_NAME, u'Multivalue'),
                x509.NameAttribute(NameOID.SURNAME, u'RDNs'),
            ]),
            x509.RelativeDistinguishedName([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA')
            ]),
        ])

        request = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).sign(private_key, hashes.SHA1(), backend)

        loaded_request = x509.load_pem_x509_csr(
            request.public_bytes(encoding=serialization.Encoding.PEM), backend
        )
        assert isinstance(loaded_request.subject, x509.Name)
        assert loaded_request.subject == subject

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_build_nonca_request_with_rsa(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(private_key, hashes.SHA1(), backend)

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ]
        basic_constraints = request.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is False
        assert basic_constraints.value.path_length is None

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    def test_build_ca_request_with_ec(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(private_key, hashes.SHA1(), backend)

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
        ]
        basic_constraints = request.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 2

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    def test_build_ca_request_with_dsa(self, backend):
        private_key = DSA_KEY_2048.private_key(backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(private_key, hashes.SHA1(), backend)

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, dsa.DSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ]
        basic_constraints = request.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 2

    def test_add_duplicate_extension(self):
        builder = x509.CertificateSigningRequestBuilder().add_extension(
            x509.BasicConstraints(True, 2), critical=True,
        )
        with pytest.raises(ValueError):
            builder.add_extension(
                x509.BasicConstraints(True, 2), critical=True,
            )

    def test_set_invalid_subject(self):
        builder = x509.CertificateSigningRequestBuilder()
        with pytest.raises(TypeError):
            builder.subject_name('NotAName')

    def test_add_invalid_extension_type(self):
        builder = x509.CertificateSigningRequestBuilder()

        with pytest.raises(TypeError):
            builder.add_extension(object(), False)

    def test_add_unsupported_extension(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"cryptography.io")]),
            critical=False,
        ).add_extension(
            DummyExtension(), False
        )
        with pytest.raises(NotImplementedError):
            builder.sign(private_key, hashes.SHA256(), backend)

    def test_key_usage(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateSigningRequestBuilder()
        request = builder.subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=False
        ).sign(private_key, hashes.SHA256(), backend)
        assert len(request.extensions) == 1
        ext = request.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        assert ext.critical is False
        assert ext.value == x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

    def test_key_usage_key_agreement_bit(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateSigningRequestBuilder()
        request = builder.subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=True
            ),
            critical=False
        ).sign(private_key, hashes.SHA256(), backend)
        assert len(request.extensions) == 1
        ext = request.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        assert ext.critical is False
        assert ext.value == x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=True
        )

    def test_add_two_extensions(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateSigningRequestBuilder()
        request = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"cryptography.io")]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(private_key, hashes.SHA1(), backend)

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        basic_constraints = request.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 2
        ext = request.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert list(ext.value) == [x509.DNSName(u"cryptography.io")]

    def test_set_subject_twice(self):
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])
        )
        with pytest.raises(ValueError):
            builder.subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
                ])
            )

    def test_subject_alt_names(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        san = x509.SubjectAlternativeName([
            x509.DNSName(u"example.com"),
            x509.DNSName(u"*.example.com"),
            x509.RegisteredID(x509.ObjectIdentifier("1.2.3.4.5.6.7")),
            x509.DirectoryName(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u'PyCA'),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, u'We heart UTF8!\u2122'
                )
            ])),
            x509.IPAddress(ipaddress.ip_address(u"127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address(u"ff::")),
            x509.OtherName(
                type_id=x509.ObjectIdentifier("1.2.3.3.3.3"),
                value=b"0\x03\x02\x01\x05"
            ),
            x509.RFC822Name(u"test@example.com"),
            x509.RFC822Name(u"email"),
            x509.RFC822Name(u"email@em\xe5\xefl.com"),
            x509.UniformResourceIdentifier(
                u"https://\u043f\u044b\u043a\u0430.cryptography"
            ),
            x509.UniformResourceIdentifier(
                u"gopher://cryptography:70/some/path"
            ),
        ])

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"SAN"),
            ])
        ).add_extension(
            san,
            critical=False,
        ).sign(private_key, hashes.SHA256(), backend)

        assert len(csr.extensions) == 1
        ext = csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert not ext.critical
        assert ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        assert ext.value == san

    def test_invalid_asn1_othername(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"SAN"),
            ])
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.OtherName(
                    type_id=x509.ObjectIdentifier("1.2.3.3.3.3"),
                    value=b"\x01\x02\x01\x05"
                ),
            ]),
            critical=False,
        )
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    def test_subject_alt_name_unsupported_general_name(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"SAN"),
            ])
        ).add_extension(
            x509.SubjectAlternativeName([FakeGeneralName("")]),
            critical=False,
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    def test_extended_key_usage(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        eku = x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CODE_SIGNING,
        ])
        builder = x509.CertificateSigningRequestBuilder()
        request = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).add_extension(
            eku, critical=False
        ).sign(private_key, hashes.SHA256(), backend)

        ext = request.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )
        assert ext.critical is False
        assert ext.value == eku

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_rsa_key_too_small(self, backend):
        private_key = rsa.generate_private_key(65537, 512, backend)
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        )

        with pytest.raises(ValueError) as exc:
            builder.sign(private_key, hashes.SHA512(), backend)

        assert str(exc.value) == "Digest too big for RSA key"

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_cert_with_aia(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        aia = x509.AuthorityInformationAccess([
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(u"http://ocsp.domain.com")
            ),
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(u"http://domain.com/ca.crt")
            )
        ])

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            aia, critical=False
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA1(), backend)

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        assert ext.value == aia

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_cert_with_ski(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        ski = x509.SubjectKeyIdentifier.from_public_key(
            subject_private_key.public_key()
        )

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            ski, critical=False
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA1(), backend)

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        assert ext.value == ski

    @pytest.mark.parametrize(
        "aki",
        [
            x509.AuthorityKeyIdentifier(
                b"\xc3\x9c\xf3\xfc\xd3F\x084\xbb\xceF\x7f\xa0|[\xf3\xe2\x08"
                b"\xcbY",
                None,
                None
            ),
            x509.AuthorityKeyIdentifier(
                b"\xc3\x9c\xf3\xfc\xd3F\x084\xbb\xceF\x7f\xa0|[\xf3\xe2\x08"
                b"\xcbY",
                [
                    x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME, u"PyCA"
                            ),
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, u"cryptography CA"
                            )
                        ])
                    )
                ],
                333
            ),
            x509.AuthorityKeyIdentifier(
                None,
                [
                    x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME, u"PyCA"
                            ),
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, u"cryptography CA"
                            )
                        ])
                    )
                ],
                333
            ),
        ]
    )
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_cert_with_aki(self, aki, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            aki, critical=False
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA256(), backend)

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        assert ext.value == aki

    def test_ocsp_nocheck(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            x509.OCSPNoCheck(), critical=False
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA256(), backend)

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.OCSP_NO_CHECK
        )
        assert isinstance(ext.value, x509.OCSPNoCheck)


@pytest.mark.requires_backend_interface(interface=DSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestDSACertificate(object):
    def test_load_dsa_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "dsa_selfsigned_ca.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA1)
        public_key = cert.public_key()
        assert isinstance(public_key, dsa.DSAPublicKey)
        num = public_key.public_numbers()
        assert num.y == int(
            "4c08bfe5f2d76649c80acf7d431f6ae2124b217abc8c9f6aca776ddfa94"
            "53b6656f13e543684cd5f6431a314377d2abfa068b7080cb8ddc065afc2"
            "dea559f0b584c97a2b235b9b69b46bc6de1aed422a6f341832618bcaae2"
            "198aba388099dafb05ff0b5efecb3b0ae169a62e1c72022af50ae68af3b"
            "033c18e6eec1f7df4692c456ccafb79cc7e08da0a5786e9816ceda651d6"
            "1b4bb7b81c2783da97cea62df67af5e85991fdc13aff10fc60e06586386"
            "b96bb78d65750f542f86951e05a6d81baadbcd35a2e5cad4119923ae6a2"
            "002091a3d17017f93c52970113cdc119970b9074ca506eac91c3dd37632"
            "5df4af6b3911ef267d26623a5a1c5df4a6d13f1c", 16
        )
        assert num.parameter_numbers.g == int(
            "4b7ced71dc353965ecc10d441a9a06fc24943a32d66429dd5ef44d43e67"
            "d789d99770aec32c0415dc92970880872da45fef8dd1e115a3e4801387b"
            "a6d755861f062fd3b6e9ea8e2641152339b828315b1528ee6c7b79458d2"
            "1f3db973f6fc303f9397174c2799dd2351282aa2d8842c357a73495bbaa"
            "c4932786414c55e60d73169f5761036fba29e9eebfb049f8a3b1b7cee6f"
            "3fbfa136205f130bee2cf5b9c38dc1095d4006f2e73335c07352c64130a"
            "1ab2b89f13b48f628d3cc3868beece9bb7beade9f830eacc6fa241425c0"
            "b3fcc0df416a0c89f7bf35668d765ec95cdcfbe9caff49cfc156c668c76"
            "fa6247676a6d3ac945844a083509c6a1b436baca", 16
        )
        assert num.parameter_numbers.p == int(
            "bfade6048e373cd4e48b677e878c8e5b08c02102ae04eb2cb5c46a523a3"
            "af1c73d16b24f34a4964781ae7e50500e21777754a670bd19a7420d6330"
            "84e5556e33ca2c0e7d547ea5f46a07a01bf8669ae3bdec042d9b2ae5e6e"
            "cf49f00ba9dac99ab6eff140d2cedf722ee62c2f9736857971444c25d0a"
            "33d2017dc36d682a1054fe2a9428dda355a851ce6e6d61e03e419fd4ca4"
            "e703313743d86caa885930f62ed5bf342d8165627681e9cc3244ba72aa2"
            "2148400a6bbe80154e855d042c9dc2a3405f1e517be9dea50562f56da93"
            "f6085f844a7e705c1f043e65751c583b80d29103e590ccb26efdaa0893d"
            "833e36468f3907cfca788a3cb790f0341c8a31bf", 16
        )
        assert num.parameter_numbers.q == int(
            "822ff5d234e073b901cf5941f58e1f538e71d40d", 16
        )

    def test_signature(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "dsa_selfsigned_ca.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert.signature == binascii.unhexlify(
            b"302c021425c4a84a936ab311ee017d3cbd9a3c650bb3ae4a02145d30c64b4326"
            b"86bdf925716b4ed059184396bcce"
        )
        r, s = decode_dss_signature(cert.signature)
        assert r == 215618264820276283222494627481362273536404860490
        assert s == 532023851299196869156027211159466197586787351758

    def test_tbs_certificate_bytes(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "dsa_selfsigned_ca.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert.tbs_certificate_bytes == binascii.unhexlify(
            b"3082051aa003020102020900a37352e0b2142f86300906072a8648ce3804033"
            b"067310b3009060355040613025553310e300c06035504081305546578617331"
            b"0f300d0603550407130641757374696e3121301f060355040a1318496e74657"
            b"26e6574205769646769747320507479204c7464311430120603550403130b50"
            b"79434120445341204341301e170d3134313132373035313431375a170d31343"
            b"13232373035313431375a3067310b3009060355040613025553310e300c0603"
            b"55040813055465786173310f300d0603550407130641757374696e3121301f0"
            b"60355040a1318496e7465726e6574205769646769747320507479204c746431"
            b"1430120603550403130b50794341204453412043413082033a3082022d06072"
            b"a8648ce380401308202200282010100bfade6048e373cd4e48b677e878c8e5b"
            b"08c02102ae04eb2cb5c46a523a3af1c73d16b24f34a4964781ae7e50500e217"
            b"77754a670bd19a7420d633084e5556e33ca2c0e7d547ea5f46a07a01bf8669a"
            b"e3bdec042d9b2ae5e6ecf49f00ba9dac99ab6eff140d2cedf722ee62c2f9736"
            b"857971444c25d0a33d2017dc36d682a1054fe2a9428dda355a851ce6e6d61e0"
            b"3e419fd4ca4e703313743d86caa885930f62ed5bf342d8165627681e9cc3244"
            b"ba72aa22148400a6bbe80154e855d042c9dc2a3405f1e517be9dea50562f56d"
            b"a93f6085f844a7e705c1f043e65751c583b80d29103e590ccb26efdaa0893d8"
            b"33e36468f3907cfca788a3cb790f0341c8a31bf021500822ff5d234e073b901"
            b"cf5941f58e1f538e71d40d028201004b7ced71dc353965ecc10d441a9a06fc2"
            b"4943a32d66429dd5ef44d43e67d789d99770aec32c0415dc92970880872da45"
            b"fef8dd1e115a3e4801387ba6d755861f062fd3b6e9ea8e2641152339b828315"
            b"b1528ee6c7b79458d21f3db973f6fc303f9397174c2799dd2351282aa2d8842"
            b"c357a73495bbaac4932786414c55e60d73169f5761036fba29e9eebfb049f8a"
            b"3b1b7cee6f3fbfa136205f130bee2cf5b9c38dc1095d4006f2e73335c07352c"
            b"64130a1ab2b89f13b48f628d3cc3868beece9bb7beade9f830eacc6fa241425"
            b"c0b3fcc0df416a0c89f7bf35668d765ec95cdcfbe9caff49cfc156c668c76fa"
            b"6247676a6d3ac945844a083509c6a1b436baca0382010500028201004c08bfe"
            b"5f2d76649c80acf7d431f6ae2124b217abc8c9f6aca776ddfa9453b6656f13e"
            b"543684cd5f6431a314377d2abfa068b7080cb8ddc065afc2dea559f0b584c97"
            b"a2b235b9b69b46bc6de1aed422a6f341832618bcaae2198aba388099dafb05f"
            b"f0b5efecb3b0ae169a62e1c72022af50ae68af3b033c18e6eec1f7df4692c45"
            b"6ccafb79cc7e08da0a5786e9816ceda651d61b4bb7b81c2783da97cea62df67"
            b"af5e85991fdc13aff10fc60e06586386b96bb78d65750f542f86951e05a6d81"
            b"baadbcd35a2e5cad4119923ae6a2002091a3d17017f93c52970113cdc119970"
            b"b9074ca506eac91c3dd376325df4af6b3911ef267d26623a5a1c5df4a6d13f1"
            b"ca381cc3081c9301d0603551d0e04160414a4fb887a13fcdeb303bbae9a1dec"
            b"a72f125a541b3081990603551d2304819130818e8014a4fb887a13fcdeb303b"
            b"bae9a1deca72f125a541ba16ba4693067310b3009060355040613025553310e"
            b"300c060355040813055465786173310f300d0603550407130641757374696e3"
            b"121301f060355040a1318496e7465726e657420576964676974732050747920"
            b"4c7464311430120603550403130b5079434120445341204341820900a37352e"
            b"0b2142f86300c0603551d13040530030101ff"
        )
        verifier = cert.public_key().verifier(
            cert.signature, cert.signature_hash_algorithm
        )
        verifier.update(cert.tbs_certificate_bytes)
        verifier.verify()


@pytest.mark.requires_backend_interface(interface=DSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestDSACertificateRequest(object):
    @pytest.mark.parametrize(
        ("path", "loader_func"),
        [
            [
                os.path.join("x509", "requests", "dsa_sha1.pem"),
                x509.load_pem_x509_csr
            ],
            [
                os.path.join("x509", "requests", "dsa_sha1.der"),
                x509.load_der_x509_csr
            ],
        ]
    )
    def test_load_dsa_request(self, path, loader_func, backend):
        request = _load_cert(path, loader_func, backend)
        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, dsa.DSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
        ]

    def test_signature(self, backend):
        request = _load_cert(
            os.path.join("x509", "requests", "dsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        assert request.signature == binascii.unhexlify(
            b"302c021461d58dc028d0110818a7d817d74235727c4acfdf0214097b52e198e"
            b"ce95de17273f0a924df23ce9d8188"
        )

    def test_tbs_certrequest_bytes(self, backend):
        request = _load_cert(
            os.path.join("x509", "requests", "dsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        assert request.tbs_certrequest_bytes == binascii.unhexlify(
            b"3082021802010030573118301606035504030c0f63727970746f677261706879"
            b"2e696f310d300b060355040a0c0450794341310b300906035504061302555331"
            b"0e300c06035504080c055465786173310f300d06035504070c0641757374696e"
            b"308201b63082012b06072a8648ce3804013082011e028181008d7fadbc09e284"
            b"aafa69154cea24177004909e519f8b35d685cde5b4ecdc9583e74d370a0f88ad"
            b"a98f026f27762fb3d5da7836f986dfcdb3589e5b925bea114defc03ef81dae30"
            b"c24bbc6df3d588e93427bba64203d4a5b1687b2b5e3b643d4c614976f89f95a3"
            b"8d3e4c89065fba97514c22c50adbbf289163a74b54859b35b7021500835de56b"
            b"d07cf7f82e2032fe78949aed117aa2ef0281801f717b5a07782fc2e4e68e311f"
            b"ea91a54edd36b86ac634d14f05a68a97eae9d2ef31fb1ef3de42c3d100df9ca6"
            b"4f5bdc2aec7bfdfb474cf831fea05853b5e059f2d24980a0ac463f1e818af352"
            b"3e3cb79a39d45fa92731897752842469cf8540b01491024eaafbce6018e8a1f4"
            b"658c343f4ba7c0b21e5376a21f4beb8491961e038184000281800713f07641f6"
            b"369bb5a9545274a2d4c01998367fb371bb9e13436363672ed68f82174c2de05c"
            b"8e839bc6de568dd50ba28d8d9d8719423aaec5557df10d773ab22d6d65cbb878"
            b"04a697bc8fd965b952f9f7e850edf13c8acdb5d753b6d10e59e0b5732e3c82ba"
            b"fa140342bc4a3bba16bd0681c8a6a2dbbb7efe6ce2b8463b170ba000"
        )
        verifier = request.public_key().verifier(
            request.signature,
            request.signature_hash_algorithm
        )
        verifier.update(request.tbs_certrequest_bytes)
        verifier.verify()


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestECDSACertificate(object):
    def test_load_ecdsa_cert(self, backend):
        _skip_curve_unsupported(backend, ec.SECP384R1())
        cert = _load_cert(
            os.path.join("x509", "ecdsa_root.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA384)
        public_key = cert.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        num = public_key.public_numbers()
        assert num.x == int(
            "dda7d9bb8ab80bfb0b7f21d2f0bebe73f3335d1abc34eadec69bbcd095f"
            "6f0ccd00bba615b51467e9e2d9fee8e630c17", 16
        )
        assert num.y == int(
            "ec0770f5cf842e40839ce83f416d3badd3a4145936789d0343ee10136c7"
            "2deae88a7a16bb543ce67dc23ff031ca3e23e", 16
        )
        assert isinstance(num.curve, ec.SECP384R1)

    def test_signature(self, backend):
        cert = _load_cert(
            os.path.join("x509", "ecdsa_root.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert.signature == binascii.unhexlify(
            b"3065023100adbcf26c3f124ad12d39c30a099773f488368c8827bbe6888d5085"
            b"a763f99e32de66930ff1ccb1098fdd6cabfa6b7fa0023039665bc2648db89e50"
            b"dca8d549a2edc7dcd1497f1701b8c8868f4e8c882ba89aa98ac5d100bdf854e2"
            b"9ae55b7cb32717"
        )
        r, s = decode_dss_signature(cert.signature)
        assert r == int(
            "adbcf26c3f124ad12d39c30a099773f488368c8827bbe6888d5085a763f99e32"
            "de66930ff1ccb1098fdd6cabfa6b7fa0",
            16
        )
        assert s == int(
            "39665bc2648db89e50dca8d549a2edc7dcd1497f1701b8c8868f4e8c882ba89a"
            "a98ac5d100bdf854e29ae55b7cb32717",
            16
        )

    def test_tbs_certificate_bytes(self, backend):
        _skip_curve_unsupported(backend, ec.SECP384R1())
        cert = _load_cert(
            os.path.join("x509", "ecdsa_root.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert.tbs_certificate_bytes == binascii.unhexlify(
            b"308201c5a0030201020210055556bcf25ea43535c3a40fd5ab4572300a06082"
            b"a8648ce3d0403033061310b300906035504061302555331153013060355040a"
            b"130c446967694365727420496e6331193017060355040b13107777772e64696"
            b"769636572742e636f6d3120301e06035504031317446967694365727420476c"
            b"6f62616c20526f6f74204733301e170d3133303830313132303030305a170d3"
            b"338303131353132303030305a3061310b300906035504061302555331153013"
            b"060355040a130c446967694365727420496e6331193017060355040b1310777"
            b"7772e64696769636572742e636f6d3120301e06035504031317446967694365"
            b"727420476c6f62616c20526f6f742047333076301006072a8648ce3d0201060"
            b"52b8104002203620004dda7d9bb8ab80bfb0b7f21d2f0bebe73f3335d1abc34"
            b"eadec69bbcd095f6f0ccd00bba615b51467e9e2d9fee8e630c17ec0770f5cf8"
            b"42e40839ce83f416d3badd3a4145936789d0343ee10136c72deae88a7a16bb5"
            b"43ce67dc23ff031ca3e23ea3423040300f0603551d130101ff040530030101f"
            b"f300e0603551d0f0101ff040403020186301d0603551d0e04160414b3db48a4"
            b"f9a1c5d8ae3641cc1163696229bc4bc6"
        )
        verifier = cert.public_key().verifier(
            cert.signature, ec.ECDSA(cert.signature_hash_algorithm)
        )
        verifier.update(cert.tbs_certificate_bytes)
        verifier.verify()

    def test_load_ecdsa_no_named_curve(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        cert = _load_cert(
            os.path.join("x509", "custom", "ec_no_named_curve.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        with pytest.raises(NotImplementedError):
            cert.public_key()


@pytest.mark.requires_backend_interface(interface=X509Backend)
@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
class TestECDSACertificateRequest(object):
    @pytest.mark.parametrize(
        ("path", "loader_func"),
        [
            [
                os.path.join("x509", "requests", "ec_sha256.pem"),
                x509.load_pem_x509_csr
            ],
            [
                os.path.join("x509", "requests", "ec_sha256.der"),
                x509.load_der_x509_csr
            ],
        ]
    )
    def test_load_ecdsa_certificate_request(self, path, loader_func, backend):
        _skip_curve_unsupported(backend, ec.SECP384R1())
        request = _load_cert(path, loader_func, backend)
        assert isinstance(request.signature_hash_algorithm, hashes.SHA256)
        public_key = request.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
        ]

    def test_signature(self, backend):
        _skip_curve_unsupported(backend, ec.SECP384R1())
        request = _load_cert(
            os.path.join("x509", "requests", "ec_sha256.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        assert request.signature == binascii.unhexlify(
            b"306502302c1a9f7de8c1787332d2307a886b476a59f172b9b0e250262f3238b1"
            b"b45ee112bb6eb35b0fb56a123b9296eb212dffc302310094cf440c95c52827d5"
            b"56ae6d76500e3008255d47c29f7ee782ed7558e51bfd76aa45df6d999ed5c463"
            b"347fe2382d1751"
        )

    def test_tbs_certrequest_bytes(self, backend):
        _skip_curve_unsupported(backend, ec.SECP384R1())
        request = _load_cert(
            os.path.join("x509", "requests", "ec_sha256.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        assert request.tbs_certrequest_bytes == binascii.unhexlify(
            b"3081d602010030573118301606035504030c0f63727970746f6772617068792"
            b"e696f310d300b060355040a0c0450794341310b300906035504061302555331"
            b"0e300c06035504080c055465786173310f300d06035504070c0641757374696"
            b"e3076301006072a8648ce3d020106052b8104002203620004de19b514c0b3c3"
            b"ae9b398ea3e26b5e816bdcf9102cad8f12fe02f9e4c9248724b39297ed7582e"
            b"04d8b32a551038d09086803a6d3fb91a1a1167ec02158b00efad39c9396462f"
            b"accff0ffaf7155812909d3726bd59fde001cff4bb9b2f5af8cbaa000"
        )
        verifier = request.public_key().verifier(
            request.signature,
            ec.ECDSA(request.signature_hash_algorithm)
        )
        verifier.update(request.tbs_certrequest_bytes)
        verifier.verify()


@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestOtherCertificate(object):
    def test_unsupported_subject_public_key_info(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom", "unsupported_subject_public_key_info.pem"
            ),
            x509.load_pem_x509_certificate,
            backend,
        )

        with pytest.raises(ValueError):
            cert.public_key()


class TestNameAttribute(object):
    def test_init_bad_oid(self):
        with pytest.raises(TypeError):
            x509.NameAttribute(None, u'value')

    def test_init_bad_value(self):
        with pytest.raises(TypeError):
            x509.NameAttribute(
                x509.ObjectIdentifier('2.999.1'),
                b'bytes'
            )

    def test_init_bad_country_code_value(self):
        with pytest.raises(ValueError):
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                u'United States'
            )

        # unicode string of length 2, but > 2 bytes
        with pytest.raises(ValueError):
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                u'\U0001F37A\U0001F37A'
            )

    def test_init_empty_value(self):
        with pytest.raises(ValueError):
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'')

    def test_country_name_type(self):
        na = x509.NameAttribute(NameOID.COUNTRY_NAME, u"US")
        assert na._type == _ASN1Type.PrintableString
        na2 = x509.NameAttribute(
            NameOID.COUNTRY_NAME, u"US", _ASN1Type.IA5String
        )
        assert na2._type == _ASN1Type.IA5String

    def test_types(self):
        na = x509.NameAttribute(NameOID.COMMON_NAME, u"common")
        assert na._type == _ASN1Type.UTF8String
        na2 = x509.NameAttribute(
            NameOID.COMMON_NAME, u"common", _ASN1Type.IA5String
        )
        assert na2._type == _ASN1Type.IA5String

    def test_invalid_type(self):
        with pytest.raises(TypeError):
            x509.NameAttribute(NameOID.COMMON_NAME, u"common", "notanenum")

    def test_eq(self):
        assert x509.NameAttribute(
            x509.ObjectIdentifier('2.999.1'), u'value'
        ) == x509.NameAttribute(
            x509.ObjectIdentifier('2.999.1'), u'value'
        )

    def test_ne(self):
        assert x509.NameAttribute(
            x509.ObjectIdentifier('2.5.4.3'), u'value'
        ) != x509.NameAttribute(
            x509.ObjectIdentifier('2.5.4.5'), u'value'
        )
        assert x509.NameAttribute(
            x509.ObjectIdentifier('2.999.1'), u'value'
        ) != x509.NameAttribute(
            x509.ObjectIdentifier('2.999.1'), u'value2'
        )
        assert x509.NameAttribute(
            x509.ObjectIdentifier('2.999.2'), u'value'
        ) != object()

    def test_repr(self):
        na = x509.NameAttribute(x509.ObjectIdentifier('2.5.4.3'), u'value')
        if six.PY3:
            assert repr(na) == (
                "<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commo"
                "nName)>, value='value')>"
            )
        else:
            assert repr(na) == (
                "<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commo"
                "nName)>, value=u'value')>"
            )


class TestRelativeDistinguishedName(object):
    def test_init_empty(self):
        with pytest.raises(ValueError):
            x509.RelativeDistinguishedName([])

    def test_init_not_nameattribute(self):
        with pytest.raises(TypeError):
            x509.RelativeDistinguishedName(["not-a-NameAttribute"])

    def test_init_duplicate_attribute(self):
        rdn = x509.RelativeDistinguishedName([
            x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1'),
            x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1'),
        ])
        assert len(rdn) == 1

    def test_hash(self):
        rdn1 = x509.RelativeDistinguishedName([
            x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1'),
            x509.NameAttribute(x509.ObjectIdentifier('2.999.2'), u'value2'),
        ])
        rdn2 = x509.RelativeDistinguishedName([
            x509.NameAttribute(x509.ObjectIdentifier('2.999.2'), u'value2'),
            x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1'),
        ])
        rdn3 = x509.RelativeDistinguishedName([
            x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1'),
            x509.NameAttribute(x509.ObjectIdentifier('2.999.2'), u'value3'),
        ])
        assert hash(rdn1) == hash(rdn2)
        assert hash(rdn1) != hash(rdn3)

    def test_eq(self):
        rdn1 = x509.RelativeDistinguishedName([
            x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1'),
            x509.NameAttribute(x509.ObjectIdentifier('2.999.2'), u'value2'),
        ])
        rdn2 = x509.RelativeDistinguishedName([
            x509.NameAttribute(x509.ObjectIdentifier('2.999.2'), u'value2'),
            x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1'),
        ])
        assert rdn1 == rdn2

    def test_ne(self):
        rdn1 = x509.RelativeDistinguishedName([
            x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1'),
            x509.NameAttribute(x509.ObjectIdentifier('2.999.2'), u'value2'),
        ])
        rdn2 = x509.RelativeDistinguishedName([
            x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1'),
            x509.NameAttribute(x509.ObjectIdentifier('2.999.2'), u'value3'),
        ])
        assert rdn1 != rdn2
        assert rdn1 != object()

    def test_iter_input(self):
        attrs = [
            x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1')
        ]
        rdn = x509.RelativeDistinguishedName(iter(attrs))
        assert list(rdn) == attrs
        assert list(rdn) == attrs

    def test_get_attributes_for_oid(self):
        oid = x509.ObjectIdentifier('2.999.1')
        attr = x509.NameAttribute(oid, u'value1')
        rdn = x509.RelativeDistinguishedName([attr])
        assert rdn.get_attributes_for_oid(oid) == [attr]
        assert rdn.get_attributes_for_oid(x509.ObjectIdentifier('1.2.3')) == []


class TestObjectIdentifier(object):
    def test_eq(self):
        oid1 = x509.ObjectIdentifier('2.999.1')
        oid2 = x509.ObjectIdentifier('2.999.1')
        assert oid1 == oid2

    def test_ne(self):
        oid1 = x509.ObjectIdentifier('2.999.1')
        assert oid1 != x509.ObjectIdentifier('2.999.2')
        assert oid1 != object()

    def test_repr(self):
        oid = x509.ObjectIdentifier("2.5.4.3")
        assert repr(oid) == "<ObjectIdentifier(oid=2.5.4.3, name=commonName)>"
        oid = x509.ObjectIdentifier("2.999.1")
        assert repr(oid) == "<ObjectIdentifier(oid=2.999.1, name=Unknown OID)>"

    def test_name_property(self):
        oid = x509.ObjectIdentifier("2.5.4.3")
        assert oid._name == 'commonName'
        oid = x509.ObjectIdentifier("2.999.1")
        assert oid._name == 'Unknown OID'

    def test_too_short(self):
        with pytest.raises(ValueError):
            x509.ObjectIdentifier("1")

    def test_invalid_input(self):
        with pytest.raises(ValueError):
            x509.ObjectIdentifier("notavalidform")

    def test_invalid_node1(self):
        with pytest.raises(ValueError):
            x509.ObjectIdentifier("7.1.37")

    def test_invalid_node2(self):
        with pytest.raises(ValueError):
            x509.ObjectIdentifier("1.50.200")

    def test_valid(self):
        x509.ObjectIdentifier("0.35.200")
        x509.ObjectIdentifier("1.39.999")
        x509.ObjectIdentifier("2.5.29.3")
        x509.ObjectIdentifier("2.999.37.5.22.8")
        x509.ObjectIdentifier("2.25.305821105408246119474742976030998643995")


class TestName(object):
    def test_eq(self):
        ava1 = x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1')
        ava2 = x509.NameAttribute(x509.ObjectIdentifier('2.999.2'), u'value2')
        name1 = x509.Name([ava1, ava2])
        name2 = x509.Name([
            x509.RelativeDistinguishedName([ava1]),
            x509.RelativeDistinguishedName([ava2]),
        ])
        name3 = x509.Name([x509.RelativeDistinguishedName([ava1, ava2])])
        name4 = x509.Name([x509.RelativeDistinguishedName([ava2, ava1])])
        assert name1 == name2
        assert name3 == name4

    def test_ne(self):
        ava1 = x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1')
        ava2 = x509.NameAttribute(x509.ObjectIdentifier('2.999.2'), u'value2')
        name1 = x509.Name([ava1, ava2])
        name2 = x509.Name([ava2, ava1])
        name3 = x509.Name([x509.RelativeDistinguishedName([ava1, ava2])])
        assert name1 != name2
        assert name1 != name3
        assert name1 != object()

    def test_hash(self):
        ava1 = x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1')
        ava2 = x509.NameAttribute(x509.ObjectIdentifier('2.999.2'), u'value2')
        name1 = x509.Name([ava1, ava2])
        name2 = x509.Name([
            x509.RelativeDistinguishedName([ava1]),
            x509.RelativeDistinguishedName([ava2]),
        ])
        name3 = x509.Name([ava2, ava1])
        name4 = x509.Name([x509.RelativeDistinguishedName([ava1, ava2])])
        name5 = x509.Name([x509.RelativeDistinguishedName([ava2, ava1])])
        assert hash(name1) == hash(name2)
        assert hash(name1) != hash(name3)
        assert hash(name1) != hash(name4)
        assert hash(name4) == hash(name5)

    def test_iter_input(self):
        attrs = [
            x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1')
        ]
        name = x509.Name(iter(attrs))
        assert list(name) == attrs
        assert list(name) == attrs

    def test_rdns(self):
        rdn1 = x509.NameAttribute(x509.ObjectIdentifier('2.999.1'), u'value1')
        rdn2 = x509.NameAttribute(x509.ObjectIdentifier('2.999.2'), u'value2')
        name1 = x509.Name([rdn1, rdn2])
        assert name1.rdns == [
            x509.RelativeDistinguishedName([rdn1]),
            x509.RelativeDistinguishedName([rdn2]),
        ]
        name2 = x509.Name([x509.RelativeDistinguishedName([rdn1, rdn2])])
        assert name2.rdns == [x509.RelativeDistinguishedName([rdn1, rdn2])]

    def test_repr(self):
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
        ])

        if six.PY3:
            assert repr(name) == (
                "<Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name"
                "=commonName)>, value='cryptography.io')>, <NameAttribute(oid="
                "<ObjectIdentifier(oid=2.5.4.10, name=organizationName)>, valu"
                "e='PyCA')>])>"
            )
        else:
            assert repr(name) == (
                "<Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name"
                "=commonName)>, value=u'cryptography.io')>, <NameAttribute(oid"
                "=<ObjectIdentifier(oid=2.5.4.10, name=organizationName)>, val"
                "ue=u'PyCA')>])>"
            )

    def test_not_nameattribute(self):
        with pytest.raises(TypeError):
            x509.Name(["not-a-NameAttribute"])

    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_bytes(self, backend):
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
        ])
        assert name.public_bytes(backend) == binascii.unhexlify(
            b"30293118301606035504030c0f63727970746f6772617068792e696f310d300"
            b"b060355040a0c0450794341"
        )


def test_random_serial_number(monkeypatch):
    sample_data = os.urandom(20)

    def notrandom(size):
        assert size == len(sample_data)
        return sample_data

    monkeypatch.setattr(os, "urandom", notrandom)

    serial_number = x509.random_serial_number()

    assert (
        serial_number == utils.int_from_bytes(sample_data, "big") >> 1
    )
    assert utils.bit_length(serial_number) < 160
