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
