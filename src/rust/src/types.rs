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
                let mut obj = py.import(self.module)?.getattr(self.names[0])?;
                for name in &self.names[1..] {
                    obj = obj.getattr(*name)?;
                }
                obj.extract()
            })
            .map(|p| p.as_ref(py))
    }
}

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
