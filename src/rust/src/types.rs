// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;

pub struct LazyPyImport {
    module: &'static str,
    names: &'static [&'static str],
    value: pyo3::sync::GILOnceCell<pyo3::PyObject>,
}

impl LazyPyImport {
    pub const fn new(module: &'static str, names: &'static [&'static str]) -> LazyPyImport {
        LazyPyImport {
            module,
            names,
            value: pyo3::sync::GILOnceCell::new(),
        }
    }

    pub fn get<'p>(&'p self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let p = self.value.get_or_try_init(py, || {
            let mut obj = py.import(self.module)?.into_any();
            for name in self.names {
                obj = obj.getattr(*name)?;
            }
            Ok::<_, pyo3::PyErr>(obj.unbind())
        })?;

        Ok(p.clone_ref(py).into_bound(py))
    }
}

pub static DATETIME_DATETIME: LazyPyImport = LazyPyImport::new("datetime", &["datetime"]);
pub static DATETIME_TIMEZONE_UTC: LazyPyImport =
    LazyPyImport::new("datetime", &["timezone", "utc"]);
pub static IPADDRESS_IPADDRESS: LazyPyImport = LazyPyImport::new("ipaddress", &["ip_address"]);
pub static IPADDRESS_IPNETWORK: LazyPyImport = LazyPyImport::new("ipaddress", &["ip_network"]);

pub static DEPRECATED_IN_36: LazyPyImport =
    LazyPyImport::new("cryptography.utils", &["DeprecatedIn36"]);
pub static DEPRECATED_IN_41: LazyPyImport =
    LazyPyImport::new("cryptography.utils", &["DeprecatedIn41"]);
pub static DEPRECATED_IN_42: LazyPyImport =
    LazyPyImport::new("cryptography.utils", &["DeprecatedIn42"]);
pub static DEPRECATED_IN_43: LazyPyImport =
    LazyPyImport::new("cryptography.utils", &["DeprecatedIn43"]);

pub static ENCODING: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["Encoding"],
);
pub static ENCODING_DER: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["Encoding", "DER"],
);
pub static ENCODING_OPENSSH: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["Encoding", "OpenSSH"],
);
pub static ENCODING_PEM: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["Encoding", "PEM"],
);
pub static ENCODING_RAW: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["Encoding", "Raw"],
);
pub static ENCODING_SMIME: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["Encoding", "SMIME"],
);
pub static ENCODING_X962: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["Encoding", "X962"],
);

pub static PRIVATE_FORMAT: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PrivateFormat"],
);
pub static PRIVATE_FORMAT_OPENSSH: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PrivateFormat", "OpenSSH"],
);
pub static PRIVATE_FORMAT_PKCS8: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PrivateFormat", "PKCS8"],
);
pub static PRIVATE_FORMAT_PKCS12: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PrivateFormat", "PKCS12"],
);
pub static PRIVATE_FORMAT_RAW: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PrivateFormat", "Raw"],
);
pub static PRIVATE_FORMAT_TRADITIONAL_OPENSSL: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PrivateFormat", "TraditionalOpenSSL"],
);

pub static PUBLIC_FORMAT: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PublicFormat"],
);
pub static PUBLIC_FORMAT_COMPRESSED_POINT: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PublicFormat", "CompressedPoint"],
);
pub static PUBLIC_FORMAT_OPENSSH: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PublicFormat", "OpenSSH"],
);
pub static PUBLIC_FORMAT_PKCS1: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PublicFormat", "PKCS1"],
);
pub static PUBLIC_FORMAT_RAW: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PublicFormat", "Raw"],
);
pub static PUBLIC_FORMAT_SUBJECT_PUBLIC_KEY_INFO: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PublicFormat", "SubjectPublicKeyInfo"],
);
pub static PUBLIC_FORMAT_UNCOMPRESSED_POINT: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PublicFormat", "UncompressedPoint"],
);

pub static PARAMETER_FORMAT_PKCS3: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["ParameterFormat", "PKCS3"],
);

pub static KEY_SERIALIZATION_ENCRYPTION: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["KeySerializationEncryption"],
);
pub static NO_ENCRYPTION: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["NoEncryption"],
);
pub static BEST_AVAILABLE_ENCRYPTION: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["BestAvailableEncryption"],
);
pub static ENCRYPTION_BUILDER: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["_KeySerializationEncryption"],
);

pub static PBES_PBESV1SHA1AND3KEYTRIPLEDESCBC: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs12",
    &["PBES", "PBESv1SHA1And3KeyTripleDESCBC"],
);
pub static PBES_PBESV2SHA256ANDAES256CBC: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs12",
    &["PBES", "PBESv2SHA256AndAES256CBC"],
);

pub static SERIALIZE_SSH_PRIVATE_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.ssh",
    &["_serialize_ssh_private_key"],
);
pub static SERIALIZE_SSH_PUBLIC_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.ssh",
    &["serialize_ssh_public_key"],
);

pub static SIG_OIDS_TO_HASH: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat._oid", &["_SIG_OIDS_TO_HASH"]);
pub static OID_NAMES: LazyPyImport = LazyPyImport::new("cryptography.hazmat._oid", &["_OID_NAMES"]);

pub static REASON_FLAGS: LazyPyImport = LazyPyImport::new("cryptography.x509", &["ReasonFlags"]);
pub static ATTRIBUTE: LazyPyImport = LazyPyImport::new("cryptography.x509", &["Attribute"]);
pub static ATTRIBUTES: LazyPyImport = LazyPyImport::new("cryptography.x509", &["Attributes"]);

pub static EXTENSION_TYPE: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["ExtensionType"]);

pub static CRL_NUMBER: LazyPyImport = LazyPyImport::new("cryptography.x509", &["CRLNumber"]);
pub static DELTA_CRL_INDICATOR: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["DeltaCRLIndicator"]);
pub static ISSUER_ALTERNATIVE_NAME: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["IssuerAlternativeName"]);
pub static AUTHORITY_INFORMATION_ACCESS: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["AuthorityInformationAccess"]);
pub static ISSUING_DISTRIBUTION_POINT: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["IssuingDistributionPoint"]);
pub static FRESHEST_CRL: LazyPyImport = LazyPyImport::new("cryptography.x509", &["FreshestCRL"]);
pub static CRL_REASON: LazyPyImport = LazyPyImport::new("cryptography.x509", &["CRLReason"]);
pub static CERTIFICATE_ISSUER: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["CertificateIssuer"]);
pub static INVALIDITY_DATE: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["InvalidityDate"]);
pub static OCSP_NONCE: LazyPyImport = LazyPyImport::new("cryptography.x509", &["OCSPNonce"]);
pub static OCSP_ACCEPTABLE_RESPONSES: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["OCSPAcceptableResponses"]);
pub static SIGNED_CERTIFICATE_TIMESTAMPS: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["SignedCertificateTimestamps"]);
pub static PRECERT_POISON: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["PrecertPoison"]);
pub static PRECERTIFICATE_SIGNED_CERTIFICATE_TIMESTAMPS: LazyPyImport = LazyPyImport::new(
    "cryptography.x509",
    &["PrecertificateSignedCertificateTimestamps"],
);
pub static DISTRIBUTION_POINT: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["DistributionPoint"]);
pub static ACCESS_DESCRIPTION: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["AccessDescription"]);
pub static AUTHORITY_KEY_IDENTIFIER: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["AuthorityKeyIdentifier"]);
pub static UNRECOGNIZED_EXTENSION: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["UnrecognizedExtension"]);
pub static EXTENSION: LazyPyImport = LazyPyImport::new("cryptography.x509", &["Extension"]);
pub static EXTENSIONS: LazyPyImport = LazyPyImport::new("cryptography.x509", &["Extensions"]);
pub static NAME: LazyPyImport = LazyPyImport::new("cryptography.x509", &["Name"]);
pub static RELATIVE_DISTINGUISHED_NAME: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["RelativeDistinguishedName"]);
pub static NAME_ATTRIBUTE: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["NameAttribute"]);
pub static NAME_CONSTRAINTS: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["NameConstraints"]);
pub static MS_CERTIFICATE_TEMPLATE: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["MSCertificateTemplate"]);
pub static CRL_DISTRIBUTION_POINTS: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["CRLDistributionPoints"]);
pub static BASIC_CONSTRAINTS: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["BasicConstraints"]);
pub static INHIBIT_ANY_POLICY: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["InhibitAnyPolicy"]);
pub static OCSP_NO_CHECK: LazyPyImport = LazyPyImport::new("cryptography.x509", &["OCSPNoCheck"]);
pub static POLICY_CONSTRAINTS: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["PolicyConstraints"]);
pub static CERTIFICATE_POLICIES: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["CertificatePolicies"]);
pub static SUBJECT_INFORMATION_ACCESS: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["SubjectInformationAccess"]);
pub static KEY_USAGE: LazyPyImport = LazyPyImport::new("cryptography.x509", &["KeyUsage"]);
pub static EXTENDED_KEY_USAGE: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["ExtendedKeyUsage"]);
pub static SUBJECT_KEY_IDENTIFIER: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["SubjectKeyIdentifier"]);
pub static TLS_FEATURE: LazyPyImport = LazyPyImport::new("cryptography.x509", &["TLSFeature"]);
pub static SUBJECT_ALTERNATIVE_NAME: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["SubjectAlternativeName"]);
pub static PRIVATE_KEY_USAGE_PERIOD: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["PrivateKeyUsagePeriod"]);
pub static POLICY_INFORMATION: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["PolicyInformation"]);
pub static USER_NOTICE: LazyPyImport = LazyPyImport::new("cryptography.x509", &["UserNotice"]);
pub static NOTICE_REFERENCE: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["NoticeReference"]);
pub static REGISTERED_ID: LazyPyImport = LazyPyImport::new("cryptography.x509", &["RegisteredID"]);
pub static DIRECTORY_NAME: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["DirectoryName"]);
pub static UNIFORM_RESOURCE_IDENTIFIER: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["UniformResourceIdentifier"]);
pub static DNS_NAME: LazyPyImport = LazyPyImport::new("cryptography.x509", &["DNSName"]);
pub static IP_ADDRESS: LazyPyImport = LazyPyImport::new("cryptography.x509", &["IPAddress"]);
pub static RFC822_NAME: LazyPyImport = LazyPyImport::new("cryptography.x509", &["RFC822Name"]);
pub static OTHER_NAME: LazyPyImport = LazyPyImport::new("cryptography.x509", &["OtherName"]);
pub static CERTIFICATE_VERSION_V1: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["Version", "v1"]);
pub static CERTIFICATE_VERSION_V3: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["Version", "v3"]);
pub static ADMISSION: LazyPyImport = LazyPyImport::new("cryptography.x509", &["Admission"]);
pub static NAMING_AUTHORITY: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["NamingAuthority"]);
pub static PROFESSION_INFO: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["ProfessionInfo"]);
pub static ADMISSIONS: LazyPyImport = LazyPyImport::new("cryptography.x509", &["Admissions"]);

pub static CRL_REASON_FLAGS: LazyPyImport =
    LazyPyImport::new("cryptography.x509.extensions", &["_CRLREASONFLAGS"]);
pub static REASON_BIT_MAPPING: LazyPyImport =
    LazyPyImport::new("cryptography.x509.extensions", &["_REASON_BIT_MAPPING"]);
pub static CRL_ENTRY_REASON_ENUM_TO_CODE: LazyPyImport = LazyPyImport::new(
    "cryptography.x509.extensions",
    &["_CRL_ENTRY_REASON_ENUM_TO_CODE"],
);
pub static TLS_FEATURE_TYPE_TO_ENUM: LazyPyImport = LazyPyImport::new(
    "cryptography.x509.extensions",
    &["_TLS_FEATURE_TYPE_TO_ENUM"],
);

pub static OCSP_RESPONSE_STATUS: LazyPyImport =
    LazyPyImport::new("cryptography.x509.ocsp", &["OCSPResponseStatus"]);
pub static OCSP_CERT_STATUS: LazyPyImport =
    LazyPyImport::new("cryptography.x509.ocsp", &["OCSPCertStatus"]);
pub static OCSP_CERT_STATUS_GOOD: LazyPyImport =
    LazyPyImport::new("cryptography.x509.ocsp", &["OCSPCertStatus", "GOOD"]);
pub static OCSP_CERT_STATUS_UNKNOWN: LazyPyImport =
    LazyPyImport::new("cryptography.x509.ocsp", &["OCSPCertStatus", "UNKNOWN"]);
pub static OCSP_RESPONDER_ENCODING_HASH: LazyPyImport =
    LazyPyImport::new("cryptography.x509.ocsp", &["OCSPResponderEncoding", "HASH"]);

pub static CERTIFICATE_TRANSPARENCY_VERSION_V1: LazyPyImport = LazyPyImport::new(
    "cryptography.x509.certificate_transparency",
    &["Version", "v1"],
);
pub static SIGNATURE_ALGORITHM: LazyPyImport = LazyPyImport::new(
    "cryptography.x509.certificate_transparency",
    &["SignatureAlgorithm"],
);
pub static LOG_ENTRY_TYPE_X509_CERTIFICATE: LazyPyImport = LazyPyImport::new(
    "cryptography.x509.certificate_transparency",
    &["LogEntryType", "X509_CERTIFICATE"],
);
pub static LOG_ENTRY_TYPE_PRE_CERTIFICATE: LazyPyImport = LazyPyImport::new(
    "cryptography.x509.certificate_transparency",
    &["LogEntryType", "PRE_CERTIFICATE"],
);

pub static ASN1_TYPE_TO_ENUM: LazyPyImport =
    LazyPyImport::new("cryptography.x509.name", &["_ASN1_TYPE_TO_ENUM"]);
pub static ASN1_TYPE_BIT_STRING: LazyPyImport =
    LazyPyImport::new("cryptography.x509.name", &["_ASN1Type", "BitString"]);
pub static ASN1_TYPE_BMP_STRING: LazyPyImport =
    LazyPyImport::new("cryptography.x509.name", &["_ASN1Type", "BMPString"]);
pub static ASN1_TYPE_UNIVERSAL_STRING: LazyPyImport =
    LazyPyImport::new("cryptography.x509.name", &["_ASN1Type", "UniversalString"]);

pub static PKCS7_OPTIONS: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs7",
    &["PKCS7Options"],
);

pub static PKCS7_BINARY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs7",
    &["PKCS7Options", "Binary"],
);
pub static PKCS7_TEXT: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs7",
    &["PKCS7Options", "Text"],
);
pub static PKCS7_NO_ATTRIBUTES: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs7",
    &["PKCS7Options", "NoAttributes"],
);
pub static PKCS7_NO_CAPABILITIES: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs7",
    &["PKCS7Options", "NoCapabilities"],
);
pub static PKCS7_NO_CERTS: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs7",
    &["PKCS7Options", "NoCerts"],
);
pub static PKCS7_DETACHED_SIGNATURE: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs7",
    &["PKCS7Options", "DetachedSignature"],
);

pub static SMIME_ENVELOPED_ENCODE: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs7",
    &["_smime_enveloped_encode"],
);

pub static SMIME_ENVELOPED_DECODE: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs7",
    &["_smime_enveloped_decode"],
);

pub static SMIME_REMOVE_TEXT_HEADERS: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs7",
    &["_smime_remove_text_headers"],
);

pub static SMIME_SIGNED_ENCODE: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs7",
    &["_smime_signed_encode"],
);

pub static PKCS12KEYANDCERTIFICATES: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs12",
    &["PKCS12KeyAndCertificates"],
);

pub static HASHES_MODULE: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.hashes", &[]);
pub static HASH_ALGORITHM: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.hashes", &["HashAlgorithm"]);
#[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
pub static EXTENDABLE_OUTPUT_FUNCTION: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.hashes",
    &["ExtendableOutputFunction"],
);
pub static SHA1: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.hashes", &["SHA1"]);
pub static SHA256: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.hashes", &["SHA256"]);

pub static PREHASHED: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.utils",
    &["Prehashed"],
);
pub static ASYMMETRIC_PADDING: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.padding",
    &["AsymmetricPadding"],
);
pub static PADDING_AUTO: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.padding",
    &["_Auto"],
);
pub static PADDING_MAX_LENGTH: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.padding",
    &["_MaxLength"],
);
pub static PADDING_DIGEST_LENGTH: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.padding",
    &["_DigestLength"],
);
pub static PKCS1V15: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.padding",
    &["PKCS1v15"],
);
pub static PSS: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.padding",
    &["PSS"],
);
pub static OAEP: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.padding",
    &["OAEP"],
);
pub static MGF1: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.padding",
    &["MGF1"],
);
pub static CALCULATE_MAX_PSS_SALT_LENGTH: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.padding",
    &["calculate_max_pss_salt_length"],
);

pub static RSA_PRIVATE_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.rsa",
    &["RSAPrivateKey"],
);
pub static RSA_PUBLIC_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.rsa",
    &["RSAPublicKey"],
);

pub static ELLIPTIC_CURVE: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.ec",
    &["EllipticCurve"],
);
pub static ELLIPTIC_CURVE_PRIVATE_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.ec",
    &["EllipticCurvePrivateKey"],
);
pub static ELLIPTIC_CURVE_PUBLIC_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.ec",
    &["EllipticCurvePublicKey"],
);
pub static CURVE_TYPES: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.ec",
    &["_CURVE_TYPES"],
);
pub static ECDSA: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.asymmetric.ec", &["ECDSA"]);
pub static ECDH: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.asymmetric.ec", &["ECDH"]);

pub static ED25519_PRIVATE_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    &["Ed25519PrivateKey"],
);
pub static ED25519_PUBLIC_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    &["Ed25519PublicKey"],
);

pub static ED448_PRIVATE_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.ed448",
    &["Ed448PrivateKey"],
);
pub static ED448_PUBLIC_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.ed448",
    &["Ed448PublicKey"],
);

pub static DSA_PRIVATE_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.dsa",
    &["DSAPrivateKey"],
);
pub static DSA_PUBLIC_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.dsa",
    &["DSAPublicKey"],
);

#[cfg(not(Py_3_11))]
pub static FFI_FROM_BUFFER: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.bindings._rust",
    &["_openssl", "ffi", "from_buffer"],
);

#[cfg(not(Py_3_11))]
pub static FFI_CAST: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.bindings._rust",
    &["_openssl", "ffi", "cast"],
);

pub static BLOCK_CIPHER_ALGORITHM: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.ciphers",
    &["BlockCipherAlgorithm"],
);

pub static TRIPLE_DES: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.decrepit.ciphers.algorithms",
    &["TripleDES"],
);
pub static DES: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.decrepit.ciphers.algorithms", &["_DES"]);
pub static AES: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.ciphers.algorithms",
    &["AES"],
);
pub static AES128: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.ciphers.algorithms",
    &["AES128"],
);
pub static AES256: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.ciphers.algorithms",
    &["AES256"],
);
pub static CHACHA20: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.ciphers.algorithms",
    &["ChaCha20"],
);
#[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_SM4"))]
pub static SM4: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.ciphers.algorithms",
    &["SM4"],
);
#[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_SEED"))]
pub static SEED: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.decrepit.ciphers.algorithms", &["SEED"]);
#[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAMELLIA"))]
pub static CAMELLIA: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.ciphers.algorithms",
    &["Camellia"],
);
#[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_BF"))]
pub static BLOWFISH: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.decrepit.ciphers.algorithms",
    &["Blowfish"],
);
#[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAST"))]
pub static CAST5: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.decrepit.ciphers.algorithms",
    &["CAST5"],
);
#[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_IDEA"))]
pub static IDEA: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.decrepit.ciphers.algorithms", &["IDEA"]);
#[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_RC4"))]
pub static ARC4: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.decrepit.ciphers.algorithms", &["ARC4"]);
pub static RC2: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.decrepit.ciphers.algorithms", &["RC2"]);

pub static MODE_WITH_INITIALIZATION_VECTOR: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.ciphers.modes",
    &["ModeWithInitializationVector"],
);
pub static MODE_WITH_TWEAK: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.ciphers.modes",
    &["ModeWithTweak"],
);
pub static MODE_WITH_NONCE: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.ciphers.modes",
    &["ModeWithNonce"],
);
pub static MODE_WITH_AUTHENTICATION_TAG: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.ciphers.modes",
    &["ModeWithAuthenticationTag"],
);
pub static CBC: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.ciphers.modes", &["CBC"]);
#[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
pub static CFB: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.ciphers.modes", &["CFB"]);
#[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
pub static CFB8: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.ciphers.modes", &["CFB8"]);
pub static OFB: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.ciphers.modes", &["OFB"]);
pub static ECB: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.ciphers.modes", &["ECB"]);
pub static CTR: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.ciphers.modes", &["CTR"]);
pub static GCM: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.ciphers.modes", &["GCM"]);
pub static XTS: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.ciphers.modes", &["XTS"]);

pub static LEGACY_PROVIDER_LOADED: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.bindings._rust",
    &["openssl", "_legacy_provider_loaded"],
);

#[cfg(test)]
mod tests {
    use super::LazyPyImport;

    #[test]
    fn test_basic() {
        pyo3::prepare_freethreaded_python();

        let v = LazyPyImport::new("foo", &["bar"]);
        pyo3::Python::with_gil(|py| {
            assert!(v.get(py).is_err());
        });
    }
}
