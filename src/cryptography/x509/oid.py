# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.hazmat.primitives import hashes


class ObjectIdentifier(object):
    def __init__(self, dotted_string):
        self._dotted_string = dotted_string

        nodes = self._dotted_string.split(".")
        intnodes = []

        # There must be at least 2 nodes, the first node must be 0..2, and
        # if less than 2, the second node cannot have a value outside the
        # range 0..39.  All nodes must be integers.
        for node in nodes:
            try:
                intnodes.append(int(node, 0))
            except ValueError:
                raise ValueError(
                    "Malformed OID: %s (non-integer nodes)" % (
                        self._dotted_string))

        if len(nodes) < 2:
            raise ValueError(
                "Malformed OID: %s (insufficient number of nodes)" % (
                    self._dotted_string))

        if intnodes[0] > 2:
            raise ValueError(
                "Malformed OID: %s (first node outside valid range)" % (
                    self._dotted_string))

        if intnodes[0] < 2 and intnodes[1] >= 40:
            raise ValueError(
                "Malformed OID: %s (second node outside valid range)" % (
                    self._dotted_string))

    def __eq__(self, other):
        if not isinstance(other, ObjectIdentifier):
            return NotImplemented

        return self.dotted_string == other.dotted_string

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return "<ObjectIdentifier(oid={0}, name={1})>".format(
            self.dotted_string,
            self._name
        )

    def __hash__(self):
        return hash(self.dotted_string)

    @property
    def _name(self):
        return _OID_NAMES.get(self, ("Unknown OID", None))[0]

    @property
    def longname(self):
        return _OID_NAMES.get(self, (None, None))[0]

    @property
    def shortname(self):
        return _OID_NAMES.get(self, (None, None))[1]

    dotted_string = utils.read_only_property("_dotted_string")


class ExtensionOID(object):
    SUBJECT_DIRECTORY_ATTRIBUTES = ObjectIdentifier("2.5.29.9")
    SUBJECT_KEY_IDENTIFIER = ObjectIdentifier("2.5.29.14")
    KEY_USAGE = ObjectIdentifier("2.5.29.15")
    SUBJECT_ALTERNATIVE_NAME = ObjectIdentifier("2.5.29.17")
    ISSUER_ALTERNATIVE_NAME = ObjectIdentifier("2.5.29.18")
    BASIC_CONSTRAINTS = ObjectIdentifier("2.5.29.19")
    NAME_CONSTRAINTS = ObjectIdentifier("2.5.29.30")
    CRL_DISTRIBUTION_POINTS = ObjectIdentifier("2.5.29.31")
    CERTIFICATE_POLICIES = ObjectIdentifier("2.5.29.32")
    POLICY_MAPPINGS = ObjectIdentifier("2.5.29.33")
    AUTHORITY_KEY_IDENTIFIER = ObjectIdentifier("2.5.29.35")
    POLICY_CONSTRAINTS = ObjectIdentifier("2.5.29.36")
    EXTENDED_KEY_USAGE = ObjectIdentifier("2.5.29.37")
    FRESHEST_CRL = ObjectIdentifier("2.5.29.46")
    INHIBIT_ANY_POLICY = ObjectIdentifier("2.5.29.54")
    AUTHORITY_INFORMATION_ACCESS = ObjectIdentifier("1.3.6.1.5.5.7.1.1")
    SUBJECT_INFORMATION_ACCESS = ObjectIdentifier("1.3.6.1.5.5.7.1.11")
    OCSP_NO_CHECK = ObjectIdentifier("1.3.6.1.5.5.7.48.1.5")
    CRL_NUMBER = ObjectIdentifier("2.5.29.20")


class CRLEntryExtensionOID(object):
    CERTIFICATE_ISSUER = ObjectIdentifier("2.5.29.29")
    CRL_REASON = ObjectIdentifier("2.5.29.21")
    INVALIDITY_DATE = ObjectIdentifier("2.5.29.24")


class NameOID(object):
    COMMON_NAME = ObjectIdentifier("2.5.4.3")
    COUNTRY_NAME = ObjectIdentifier("2.5.4.6")
    LOCALITY_NAME = ObjectIdentifier("2.5.4.7")
    STATE_OR_PROVINCE_NAME = ObjectIdentifier("2.5.4.8")
    STREET_ADDRESS = ObjectIdentifier("2.5.4.9")
    ORGANIZATION_NAME = ObjectIdentifier("2.5.4.10")
    ORGANIZATIONAL_UNIT_NAME = ObjectIdentifier("2.5.4.11")
    SERIAL_NUMBER = ObjectIdentifier("2.5.4.5")
    SURNAME = ObjectIdentifier("2.5.4.4")
    GIVEN_NAME = ObjectIdentifier("2.5.4.42")
    TITLE = ObjectIdentifier("2.5.4.12")
    GENERATION_QUALIFIER = ObjectIdentifier("2.5.4.44")
    X500_UNIQUE_IDENTIFIER = ObjectIdentifier("2.5.4.45")
    DN_QUALIFIER = ObjectIdentifier("2.5.4.46")
    PSEUDONYM = ObjectIdentifier("2.5.4.65")
    USER_ID = ObjectIdentifier("0.9.2342.19200300.100.1.1")
    DOMAIN_COMPONENT = ObjectIdentifier("0.9.2342.19200300.100.1.25")
    EMAIL_ADDRESS = ObjectIdentifier("1.2.840.113549.1.9.1")
    JURISDICTION_COUNTRY_NAME = ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3")
    JURISDICTION_LOCALITY_NAME = ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.1")
    JURISDICTION_STATE_OR_PROVINCE_NAME = ObjectIdentifier(
        "1.3.6.1.4.1.311.60.2.1.2"
    )
    BUSINESS_CATEGORY = ObjectIdentifier("2.5.4.15")
    POSTAL_ADDRESS = ObjectIdentifier("2.5.4.16")
    POSTAL_CODE = ObjectIdentifier("2.5.4.17")


class SignatureAlgorithmOID(object):
    RSA_WITH_MD5 = ObjectIdentifier("1.2.840.113549.1.1.4")
    RSA_WITH_SHA1 = ObjectIdentifier("1.2.840.113549.1.1.5")
    # This is an alternate OID for RSA with SHA1 that is occasionally seen
    _RSA_WITH_SHA1 = ObjectIdentifier("1.3.14.3.2.29")
    RSA_WITH_SHA224 = ObjectIdentifier("1.2.840.113549.1.1.14")
    RSA_WITH_SHA256 = ObjectIdentifier("1.2.840.113549.1.1.11")
    RSA_WITH_SHA384 = ObjectIdentifier("1.2.840.113549.1.1.12")
    RSA_WITH_SHA512 = ObjectIdentifier("1.2.840.113549.1.1.13")
    ECDSA_WITH_SHA1 = ObjectIdentifier("1.2.840.10045.4.1")
    ECDSA_WITH_SHA224 = ObjectIdentifier("1.2.840.10045.4.3.1")
    ECDSA_WITH_SHA256 = ObjectIdentifier("1.2.840.10045.4.3.2")
    ECDSA_WITH_SHA384 = ObjectIdentifier("1.2.840.10045.4.3.3")
    ECDSA_WITH_SHA512 = ObjectIdentifier("1.2.840.10045.4.3.4")
    DSA_WITH_SHA1 = ObjectIdentifier("1.2.840.10040.4.3")
    DSA_WITH_SHA224 = ObjectIdentifier("2.16.840.1.101.3.4.3.1")
    DSA_WITH_SHA256 = ObjectIdentifier("2.16.840.1.101.3.4.3.2")


_SIG_OIDS_TO_HASH = {
    SignatureAlgorithmOID.RSA_WITH_MD5: hashes.MD5(),
    SignatureAlgorithmOID.RSA_WITH_SHA1: hashes.SHA1(),
    SignatureAlgorithmOID._RSA_WITH_SHA1: hashes.SHA1(),
    SignatureAlgorithmOID.RSA_WITH_SHA224: hashes.SHA224(),
    SignatureAlgorithmOID.RSA_WITH_SHA256: hashes.SHA256(),
    SignatureAlgorithmOID.RSA_WITH_SHA384: hashes.SHA384(),
    SignatureAlgorithmOID.RSA_WITH_SHA512: hashes.SHA512(),
    SignatureAlgorithmOID.ECDSA_WITH_SHA1: hashes.SHA1(),
    SignatureAlgorithmOID.ECDSA_WITH_SHA224: hashes.SHA224(),
    SignatureAlgorithmOID.ECDSA_WITH_SHA256: hashes.SHA256(),
    SignatureAlgorithmOID.ECDSA_WITH_SHA384: hashes.SHA384(),
    SignatureAlgorithmOID.ECDSA_WITH_SHA512: hashes.SHA512(),
    SignatureAlgorithmOID.DSA_WITH_SHA1: hashes.SHA1(),
    SignatureAlgorithmOID.DSA_WITH_SHA224: hashes.SHA224(),
    SignatureAlgorithmOID.DSA_WITH_SHA256: hashes.SHA256()
}


class ExtendedKeyUsageOID(object):
    SERVER_AUTH = ObjectIdentifier("1.3.6.1.5.5.7.3.1")
    CLIENT_AUTH = ObjectIdentifier("1.3.6.1.5.5.7.3.2")
    CODE_SIGNING = ObjectIdentifier("1.3.6.1.5.5.7.3.3")
    EMAIL_PROTECTION = ObjectIdentifier("1.3.6.1.5.5.7.3.4")
    TIME_STAMPING = ObjectIdentifier("1.3.6.1.5.5.7.3.8")
    OCSP_SIGNING = ObjectIdentifier("1.3.6.1.5.5.7.3.9")


class AuthorityInformationAccessOID(object):
    CA_ISSUERS = ObjectIdentifier("1.3.6.1.5.5.7.48.2")
    OCSP = ObjectIdentifier("1.3.6.1.5.5.7.48.1")


class CertificatePoliciesOID(object):
    CPS_QUALIFIER = ObjectIdentifier("1.3.6.1.5.5.7.2.1")
    CPS_USER_NOTICE = ObjectIdentifier("1.3.6.1.5.5.7.2.2")
    ANY_POLICY = ObjectIdentifier("2.5.29.32.0")


# ObjectIdentifier -> long name, short name
_OID_NAMES = {
    NameOID.COMMON_NAME: ("commonName", "CN"),
    NameOID.COUNTRY_NAME: ("countryName", "C"),
    NameOID.LOCALITY_NAME: ("localityName", "L"),
    NameOID.STATE_OR_PROVINCE_NAME: ("stateOrProvinceName", "ST"),
    NameOID.STREET_ADDRESS: ("streetAddress", "street"),
    NameOID.ORGANIZATION_NAME: ("organizationName", "O"),
    NameOID.ORGANIZATIONAL_UNIT_NAME: ("organizationalUnitName", "OU"),
    NameOID.SERIAL_NUMBER: ("serialNumber", "serialNumber"),
    NameOID.SURNAME: ("surname", "SN"),
    NameOID.GIVEN_NAME: ("givenName", "GN"),
    NameOID.TITLE: ("title", "title"),
    NameOID.GENERATION_QUALIFIER: (
        "generationQualifier", "generationQualifier"
    ),
    NameOID.X500_UNIQUE_IDENTIFIER: (
        "x500UniqueIdentifier", "x500UniqueIdentifier"
    ),
    NameOID.DN_QUALIFIER: ("dnQualifier", "dnQualifier"),
    NameOID.PSEUDONYM: ("pseudonym", "pseudonym"),
    NameOID.USER_ID: ("userID", "UID"),
    NameOID.DOMAIN_COMPONENT: ("domainComponent", "DN"),
    NameOID.EMAIL_ADDRESS: ("emailAddress", "emailAddress"),
    NameOID.JURISDICTION_COUNTRY_NAME: (
        "jurisdictionCountryName", "jurisdictionC"
    ),
    NameOID.JURISDICTION_LOCALITY_NAME: (
        "jurisdictionLocalityName", "jurisdictionL"
    ),
    NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME: (
        "jurisdictionStateOrProvinceName", "jurisdictionST"
    ),
    NameOID.BUSINESS_CATEGORY: ("businessCategory", "businessCategory"),
    NameOID.POSTAL_ADDRESS: ("postalAddress", "postalAddress"),
    NameOID.POSTAL_CODE: ("postalCode", "postalCode"),

    SignatureAlgorithmOID.RSA_WITH_MD5: (
        "md5WithRSAEncryption", "RSA-MD5"
    ),
    SignatureAlgorithmOID.RSA_WITH_SHA1: (
        "sha1WithRSAEncryption", "RSA-SHA1"
    ),
    SignatureAlgorithmOID.RSA_WITH_SHA224: (
        "sha224WithRSAEncryption", "RSA-SHA224"
    ),
    SignatureAlgorithmOID.RSA_WITH_SHA256: (
        "sha256WithRSAEncryption", "RSA-SHA256"
    ),
    SignatureAlgorithmOID.RSA_WITH_SHA384: (
        "sha384WithRSAEncryption", "RSA-SHA384"
    ),
    SignatureAlgorithmOID.RSA_WITH_SHA512: (
        "sha512WithRSAEncryption", "RSA-SHA512"
    ),
    SignatureAlgorithmOID.ECDSA_WITH_SHA1: ("ecdsa-with-SHA1", None),
    SignatureAlgorithmOID.ECDSA_WITH_SHA224: ("ecdsa-with-SHA224", None),
    SignatureAlgorithmOID.ECDSA_WITH_SHA256: ("ecdsa-with-SHA256", None),
    SignatureAlgorithmOID.ECDSA_WITH_SHA384: ("ecdsa-with-SHA384", None),
    SignatureAlgorithmOID.ECDSA_WITH_SHA512: ("ecdsa-with-SHA512", None),
    SignatureAlgorithmOID.DSA_WITH_SHA1: ("dsa-with-sha1", "DSA-SHA1"),
    SignatureAlgorithmOID.DSA_WITH_SHA224: ("dsa-with-sha224", None),
    SignatureAlgorithmOID.DSA_WITH_SHA256: ("dsa-with-sha256", None),
    ExtendedKeyUsageOID.SERVER_AUTH: ("serverAuth", None),
    ExtendedKeyUsageOID.CLIENT_AUTH: ("clientAuth", None),
    ExtendedKeyUsageOID.CODE_SIGNING: ("codeSigning", None),
    ExtendedKeyUsageOID.EMAIL_PROTECTION: ("emailProtection", None),
    ExtendedKeyUsageOID.TIME_STAMPING: ("timeStamping", None),
    ExtendedKeyUsageOID.OCSP_SIGNING: ("OCSPSigning", None),
    ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES: (
        "subjectDirectoryAttributes", None
    ),
    ExtensionOID.SUBJECT_KEY_IDENTIFIER: ("subjectKeyIdentifier", None),
    ExtensionOID.KEY_USAGE: ("keyUsage", None),
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: ("subjectAltName", None),
    ExtensionOID.ISSUER_ALTERNATIVE_NAME: ("issuerAltName", None),
    ExtensionOID.BASIC_CONSTRAINTS: ("basicConstraints", None),
    CRLEntryExtensionOID.CRL_REASON: ("cRLReason", None),
    CRLEntryExtensionOID.INVALIDITY_DATE: ("invalidityDate", None),
    CRLEntryExtensionOID.CERTIFICATE_ISSUER: ("certificateIssuer", None),
    ExtensionOID.NAME_CONSTRAINTS: ("nameConstraints", None),
    ExtensionOID.CRL_DISTRIBUTION_POINTS: ("cRLDistributionPoints", None),
    ExtensionOID.CERTIFICATE_POLICIES: ("certificatePolicies", None),
    ExtensionOID.POLICY_MAPPINGS: ("policyMappings", None),
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER: ("authorityKeyIdentifier", None),
    ExtensionOID.POLICY_CONSTRAINTS: ("policyConstraints", None),
    ExtensionOID.EXTENDED_KEY_USAGE: ("extendedKeyUsage", None),
    ExtensionOID.FRESHEST_CRL: ("freshestCRL", None),
    ExtensionOID.INHIBIT_ANY_POLICY: ("inhibitAnyPolicy", None),
    ExtensionOID.AUTHORITY_INFORMATION_ACCESS: ("authorityInfoAccess", None),
    ExtensionOID.SUBJECT_INFORMATION_ACCESS: ("subjectInfoAccess", None),
    ExtensionOID.OCSP_NO_CHECK: ("OCSPNoCheck", None),
    ExtensionOID.CRL_NUMBER: ("cRLNumber", None),
    AuthorityInformationAccessOID.OCSP: ("OCSP", None),
    AuthorityInformationAccessOID.CA_ISSUERS: ("caIssuers", None),
    CertificatePoliciesOID.CPS_QUALIFIER: ("id-qt-cps", None),
    CertificatePoliciesOID.CPS_USER_NOTICE: ("id-qt-unotice", None),
}
