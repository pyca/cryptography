# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography.x509.base import (
    AccessDescription, AuthorityInformationAccess, AuthorityKeyIdentifier,
    BasicConstraints, CRLDistributionPoints, Certificate, CertificateBuilder,
    CertificatePolicies, CertificateRevocationList, CertificateSigningRequest,
    CertificateSigningRequestBuilder, DNSName, DirectoryName,
    DistributionPoint, DuplicateExtension, ExtendedKeyUsage,
    Extension, ExtensionNotFound, ExtensionType, Extensions, GeneralName,
    GeneralNames, IPAddress, InhibitAnyPolicy, InvalidVersion,
    IssuerAlternativeName, KeyUsage, NameConstraints,
    NoticeReference, OCSPNoCheck, ObjectIdentifier, OtherName,
    PolicyInformation, RFC822Name, ReasonFlags, RegisteredID,
    RevokedCertificate, SubjectAlternativeName, SubjectKeyIdentifier,
    UniformResourceIdentifier, UnsupportedExtension,
    UnsupportedGeneralNameType, UserNotice, Version, _GENERAL_NAMES,
    load_der_x509_certificate,
    load_der_x509_csr, load_pem_x509_certificate, load_pem_x509_csr,
)
from cryptography.x509.name import Name, NameAttribute
from cryptography.x509.oid import (
    ExtensionOID, OID_ANY_POLICY,
    OID_CA_ISSUERS, OID_CERTIFICATE_ISSUER, OID_CLIENT_AUTH,
    OID_CODE_SIGNING, OID_COMMON_NAME, OID_COUNTRY_NAME, OID_CPS_QUALIFIER,
    OID_CPS_USER_NOTICE, OID_CRL_REASON,
    OID_DN_QUALIFIER, OID_DOMAIN_COMPONENT, OID_DSA_WITH_SHA1,
    OID_DSA_WITH_SHA224, OID_DSA_WITH_SHA256, OID_ECDSA_WITH_SHA1,
    OID_ECDSA_WITH_SHA224, OID_ECDSA_WITH_SHA256, OID_ECDSA_WITH_SHA384,
    OID_ECDSA_WITH_SHA512, OID_EMAIL_ADDRESS, OID_EMAIL_PROTECTION,
    OID_GENERATION_QUALIFIER, OID_GIVEN_NAME, OID_INVALIDITY_DATE,
    OID_LOCALITY_NAME, OID_OCSP, OID_OCSP_SIGNING,
    OID_ORGANIZATIONAL_UNIT_NAME, OID_ORGANIZATION_NAME,
    OID_PSEUDONYM, OID_RSA_WITH_MD5, OID_RSA_WITH_SHA1, OID_RSA_WITH_SHA224,
    OID_RSA_WITH_SHA256, OID_RSA_WITH_SHA384, OID_RSA_WITH_SHA512,
    OID_SERIAL_NUMBER, OID_SERVER_AUTH, OID_STATE_OR_PROVINCE_NAME,
    OID_SURNAME, OID_TIME_STAMPING, OID_TITLE, _SIG_OIDS_TO_HASH
)


OID_AUTHORITY_INFORMATION_ACCESS = ExtensionOID.AUTHORITY_INFORMATION_ACCESS
OID_AUTHORITY_KEY_IDENTIFIER = ExtensionOID.AUTHORITY_KEY_IDENTIFIER
OID_BASIC_CONSTRAINTS = ExtensionOID.BASIC_CONSTRAINTS
OID_CERTIFICATE_POLICIES = ExtensionOID.CERTIFICATE_POLICIES
OID_CRL_DISTRIBUTION_POINTS = ExtensionOID.CRL_DISTRIBUTION_POINTS
OID_EXTENDED_KEY_USAGE = ExtensionOID.EXTENDED_KEY_USAGE
OID_FRESHEST_CRL = ExtensionOID.FRESHEST_CRL
OID_INHIBIT_ANY_POLICY = ExtensionOID.INHIBIT_ANY_POLICY
OID_ISSUER_ALTERNATIVE_NAME = ExtensionOID.ISSUER_ALTERNATIVE_NAME
OID_KEY_USAGE = ExtensionOID.KEY_USAGE
OID_NAME_CONSTRAINTS = ExtensionOID.NAME_CONSTRAINTS
OID_OCSP_NO_CHECK = ExtensionOID.OCSP_NO_CHECK
OID_POLICY_CONSTRAINTS = ExtensionOID.POLICY_CONSTRAINTS
OID_POLICY_MAPPINGS = ExtensionOID.POLICY_MAPPINGS
OID_SUBJECT_ALTERNATIVE_NAME = ExtensionOID.SUBJECT_ALTERNATIVE_NAME
OID_SUBJECT_DIRECTORY_ATTRIBUTES = ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES
OID_SUBJECT_INFORMATION_ACCESS = ExtensionOID.SUBJECT_INFORMATION_ACCESS
OID_SUBJECT_KEY_IDENTIFIER = ExtensionOID.SUBJECT_KEY_IDENTIFIER


__all__ = [
    "load_pem_x509_certificate",
    "load_der_x509_certificate",
    "load_pem_x509_csr",
    "load_der_x509_csr",
    "InvalidVersion",
    "DuplicateExtension",
    "UnsupportedExtension",
    "ExtensionNotFound",
    "UnsupportedGeneralNameType",
    "NameAttribute",
    "Name",
    "ObjectIdentifier",
    "ExtensionType",
    "Extensions",
    "Extension",
    "ExtendedKeyUsage",
    "OCSPNoCheck",
    "BasicConstraints",
    "KeyUsage",
    "AuthorityInformationAccess",
    "AccessDescription",
    "CertificatePolicies",
    "PolicyInformation",
    "UserNotice",
    "NoticeReference",
    "SubjectKeyIdentifier",
    "NameConstraints",
    "CRLDistributionPoints",
    "DistributionPoint",
    "ReasonFlags",
    "InhibitAnyPolicy",
    "SubjectAlternativeName",
    "IssuerAlternativeName",
    "AuthorityKeyIdentifier",
    "GeneralNames",
    "GeneralName",
    "RFC822Name",
    "DNSName",
    "UniformResourceIdentifier",
    "RegisteredID",
    "DirectoryName",
    "IPAddress",
    "OtherName",
    "Certificate",
    "CertificateRevocationList",
    "CertificateSigningRequest",
    "RevokedCertificate",
    "CertificateSigningRequestBuilder",
    "CertificateBuilder",
    "Version",
    "OID_CRL_REASON",
    "OID_INVALIDITY_DATE",
    "OID_CERTIFICATE_ISSUER",
    "OID_COMMON_NAME",
    "OID_COUNTRY_NAME",
    "OID_LOCALITY_NAME",
    "OID_STATE_OR_PROVINCE_NAME",
    "OID_ORGANIZATION_NAME",
    "OID_ORGANIZATIONAL_UNIT_NAME",
    "OID_SERIAL_NUMBER",
    "OID_SURNAME",
    "OID_GIVEN_NAME",
    "OID_TITLE",
    "OID_GENERATION_QUALIFIER",
    "OID_DN_QUALIFIER",
    "OID_PSEUDONYM",
    "OID_DOMAIN_COMPONENT",
    "OID_EMAIL_ADDRESS",
    "OID_RSA_WITH_MD5",
    "OID_RSA_WITH_SHA1",
    "OID_RSA_WITH_SHA224",
    "OID_RSA_WITH_SHA256",
    "OID_RSA_WITH_SHA384",
    "OID_RSA_WITH_SHA512",
    "OID_ECDSA_WITH_SHA1",
    "OID_ECDSA_WITH_SHA224",
    "OID_ECDSA_WITH_SHA256",
    "OID_ECDSA_WITH_SHA384",
    "OID_ECDSA_WITH_SHA512",
    "OID_DSA_WITH_SHA1",
    "OID_DSA_WITH_SHA224",
    "OID_DSA_WITH_SHA256",
    "_SIG_OIDS_TO_HASH",
    "OID_CPS_QUALIFIER",
    "OID_CPS_USER_NOTICE",
    "OID_ANY_POLICY",
    "OID_CA_ISSUERS",
    "OID_OCSP",
    "OID_SERVER_AUTH",
    "OID_CLIENT_AUTH",
    "OID_CODE_SIGNING",
    "OID_EMAIL_PROTECTION",
    "OID_TIME_STAMPING",
    "OID_OCSP_SIGNING",
    "_GENERAL_NAMES",
]
