// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

pub struct LazyPyImport {
    module: &'static str,
    names: &'static [&'static str],
    value: pyo3::once_cell::GILOnceCell<pyo3::PyObject>,
}

impl LazyPyImport {
    pub const fn new(module: &'static str, names: &'static [&'static str]) -> LazyPyImport {
        LazyPyImport {
            module,
            names,
            value: pyo3::once_cell::GILOnceCell::new(),
        }
    }

    pub fn get<'p>(&'p self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        self.value
            .get_or_try_init(py, || {
                let mut obj = py.import(self.module)?.as_ref();
                for name in self.names {
                    obj = obj.getattr(*name)?;
                }
                obj.extract()
            })
            .map(|p| p.as_ref(py))
    }
}

pub static DEPRECATED_IN_36: LazyPyImport =
    LazyPyImport::new("cryptography.utils", &["DeprecatedIn36"]);

pub static LOAD_DER_PUBLIC_KEY: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["load_der_public_key"],
);

pub static ENCODING_DER: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["Encoding", "DER"],
);
pub static ENCODING_SMIME: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["Encoding", "SMIME"],
);

pub static PRIVATE_FORMAT_PKCS8: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PrivateFormat", "PKCS8"],
);

pub static PUBLIC_FORMAT_SUBJECT_PUBLIC_KEY_INFO: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["PublicFormat", "SubjectPublicKeyInfo"],
);

pub static PARAMETER_FORMAT_PKCS3: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization",
    &["ParameterFormat", "PKCS3"],
);

pub static SIG_OIDS_TO_HASH: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat._oid", &["_SIG_OIDS_TO_HASH"]);

pub static REASON_FLAGS: LazyPyImport = LazyPyImport::new("cryptography.x509", &["ReasonFlags"]);
pub static ATTRIBUTE: LazyPyImport = LazyPyImport::new("cryptography.x509", &["Attribute"]);
pub static ATTRIBUTES: LazyPyImport = LazyPyImport::new("cryptography.x509", &["Attributes"]);

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

pub static SMIME_ENCODE: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.serialization.pkcs7",
    &["_smime_encode"],
);

pub static HASHES_MODULE: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.hashes", &[]);
pub static HASH_ALGORITHM: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.hashes", &["HashAlgorithm"]);
pub static EXTENDABLE_OUTPUT_FUNCTION: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.hashes",
    &["ExtendableOutputFunction"],
);
pub static SHA1: LazyPyImport =
    LazyPyImport::new("cryptography.hazmat.primitives.hashes", &["SHA1"]);

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

pub static CRL_ENTRY_REASON_ENUM_TO_CODE: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.backends.openssl.decode_asn1",
    &["_CRL_ENTRY_REASON_ENUM_TO_CODE"],
);
pub static CALCULATE_DIGEST_AND_ALGORITHM: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.backends.openssl.utils",
    &["_calculate_digest_and_algorithm"],
);

pub static RSA_PUBLIC_NUMBERS: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.rsa",
    &["RSAPublicNumbers"],
);
pub static RSA_PRIVATE_NUMBERS: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.rsa",
    &["RSAPrivateNumbers"],
);

pub static DH_PARAMETER_NUMBERS: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.dh",
    &["DHParameterNumbers"],
);
pub static DH_PUBLIC_NUMBERS: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.dh",
    &["DHPublicNumbers"],
);
pub static DH_PRIVATE_NUMBERS: LazyPyImport = LazyPyImport::new(
    "cryptography.hazmat.primitives.asymmetric.dh",
    &["DHPrivateNumbers"],
);

pub static EXTRACT_BUFFER_LENGTH: LazyPyImport =
    LazyPyImport::new("cryptography.utils", &["_extract_buffer_length"]);

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
