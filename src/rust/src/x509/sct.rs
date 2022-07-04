// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::PyAsn1Error;
use pyo3::types::IntoPyDict;
use pyo3::ToPyObject;
use std::collections::hash_map::DefaultHasher;
use std::convert::{TryFrom, TryInto};
use std::hash::{Hash, Hasher};

struct TLSReader<'a> {
    data: &'a [u8],
}

impl<'a> TLSReader<'a> {
    fn new(data: &'a [u8]) -> TLSReader<'a> {
        TLSReader { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn read_byte(&mut self) -> Result<u8, PyAsn1Error> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PyAsn1Error> {
        if length > self.data.len() {
            return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                "Invalid SCT length",
            )));
        }
        let (result, data) = self.data.split_at(length);
        self.data = data;
        Ok(result)
    }

    fn read_length_prefixed(&mut self) -> Result<TLSReader<'a>, PyAsn1Error> {
        let length = u16::from_be_bytes(self.read_exact(2)?.try_into().unwrap());
        Ok(TLSReader::new(self.read_exact(length.into())?))
    }
}

#[derive(Clone)]
pub(crate) enum LogEntryType {
    Certificate,
    PreCertificate,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HashAlgorithm {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl TryFrom<u8> for HashAlgorithm {
    type Error = pyo3::PyErr;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => HashAlgorithm::Md5,
            2 => HashAlgorithm::Sha1,
            3 => HashAlgorithm::Sha224,
            4 => HashAlgorithm::Sha256,
            5 => HashAlgorithm::Sha384,
            6 => HashAlgorithm::Sha512,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Invalid/unsupported hash algorithm for SCT: {}",
                    value
                )))
            }
        })
    }
}

impl HashAlgorithm {
    fn to_attr(&self) -> &'static str {
        match self {
            HashAlgorithm::Md5 => "MD5",
            HashAlgorithm::Sha1 => "SHA1",
            HashAlgorithm::Sha224 => "SHA224",
            HashAlgorithm::Sha256 => "SHA256",
            HashAlgorithm::Sha384 => "SHA384",
            HashAlgorithm::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SignatureAlgorithm {
    Rsa,
    Dsa,
    Ecdsa,
}

impl SignatureAlgorithm {
    fn to_attr(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Rsa => "RSA",
            SignatureAlgorithm::Dsa => "DSA",
            SignatureAlgorithm::Ecdsa => "ECDSA",
        }
    }
}

impl TryFrom<u8> for SignatureAlgorithm {
    type Error = pyo3::PyErr;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => SignatureAlgorithm::Rsa,
            2 => SignatureAlgorithm::Dsa,
            3 => SignatureAlgorithm::Ecdsa,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Invalid/unsupported signature algorithm for SCT: {}",
                    value
                )))
            }
        })
    }
}

#[pyo3::prelude::pyclass]
pub(crate) struct Sct {
    log_id: [u8; 32],
    timestamp: u64,
    entry_type: LogEntryType,
    hash_algorithm: HashAlgorithm,
    signature_algorithm: SignatureAlgorithm,
    // TODO: These could be 'self references back into sct_data with ouroboros.
    signature: Vec<u8>,
    extension_bytes: Vec<u8>,
    pub(crate) sct_data: Vec<u8>,
}

#[pyo3::prelude::pymethods]
impl Sct {
    #[getter]
    fn version<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        py.import("cryptography.x509.certificate_transparency")?
            .getattr(crate::intern!(py, "Version"))?
            .getattr(crate::intern!(py, "v1"))
    }

    #[getter]
    fn log_id(&self) -> &[u8] {
        &self.log_id
    }

    #[getter]
    fn timestamp<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let datetime_class = py
            .import("datetime")?
            .getattr(crate::intern!(py, "datetime"))?;
        datetime_class
            .call_method1("utcfromtimestamp", (self.timestamp / 1000,))?
            .call_method(
                "replace",
                (),
                Some(vec![("microsecond", self.timestamp % 1000 * 1000)].into_py_dict(py)),
            )
    }

    #[getter]
    fn entry_type<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let et_class = py
            .import("cryptography.x509.certificate_transparency")?
            .getattr(crate::intern!(py, "LogEntryType"))?;
        let attr_name = match self.entry_type {
            LogEntryType::Certificate => "X509_CERTIFICATE",
            LogEntryType::PreCertificate => "PRE_CERTIFICATE",
        };
        et_class.getattr(attr_name)
    }

    #[getter]
    fn signature_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let hashes_mod = py.import("cryptography.hazmat.primitives.hashes")?;
        hashes_mod.call_method0(self.hash_algorithm.to_attr())
    }

    #[getter]
    fn signature_algorithm<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let sa_class = py
            .import("cryptography.x509.certificate_transparency")?
            .getattr(crate::intern!(py, "SignatureAlgorithm"))?;
        sa_class.getattr(self.signature_algorithm.to_attr())
    }

    #[getter]
    fn signature(&self) -> &[u8] {
        &self.signature
    }

    #[getter]
    fn extension_bytes(&self) -> &[u8] {
        &self.extension_bytes
    }
}

#[pyo3::prelude::pyproto]
impl pyo3::PyObjectProtocol for Sct {
    fn __richcmp__(
        &self,
        other: pyo3::PyRef<Sct>,
        op: pyo3::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => Ok(self.sct_data == other.sct_data),
            pyo3::basic::CompareOp::Ne => Ok(self.sct_data != other.sct_data),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "SCTs cannot be ordered",
            )),
        }
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.sct_data.hash(&mut hasher);
        hasher.finish()
    }
}

pub(crate) fn parse_scts(
    py: pyo3::Python<'_>,
    data: &[u8],
    entry_type: LogEntryType,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let mut reader = TLSReader::new(data).read_length_prefixed()?;

    let py_scts = pyo3::types::PyList::empty(py);
    while !reader.is_empty() {
        let mut sct_data = reader.read_length_prefixed()?;
        let raw_sct_data = sct_data.data.to_vec();
        let version = sct_data.read_byte()?;
        if version != 0 {
            return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                "Invalid SCT version",
            )));
        }
        let log_id = sct_data.read_exact(32)?.try_into().unwrap();
        let timestamp = u64::from_be_bytes(sct_data.read_exact(8)?.try_into().unwrap());
        let extension_bytes = sct_data.read_length_prefixed()?.data.to_vec();
        let hash_algorithm = sct_data.read_byte()?.try_into()?;
        let signature_algorithm = sct_data.read_byte()?.try_into()?;

        let signature = sct_data.read_length_prefixed()?.data.to_vec();

        let sct = Sct {
            log_id,
            timestamp,
            entry_type: entry_type.clone(),
            hash_algorithm,
            signature_algorithm,
            signature,
            extension_bytes,
            sct_data: raw_sct_data,
        };
        py_scts.append(pyo3::PyCell::new(py, sct)?)?;
    }
    Ok(py_scts.to_object(py))
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_class::<Sct>()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_try_from() {
        for (n, ha) in &[
            (1_u8, HashAlgorithm::Md5),
            (2_u8, HashAlgorithm::Sha1),
            (3_u8, HashAlgorithm::Sha224),
            (4_u8, HashAlgorithm::Sha256),
            (5_u8, HashAlgorithm::Sha384),
            (6_u8, HashAlgorithm::Sha512),
        ] {
            let res = HashAlgorithm::try_from(*n).unwrap();
            assert_eq!(&res, ha);
        }

        // We don't support "none" hash algorithms.
        assert!(HashAlgorithm::try_from(0).is_err());
        assert!(HashAlgorithm::try_from(7).is_err());
    }

    #[test]
    fn test_hash_algorithm_to_attr() {
        for (ha, attr) in &[
            (HashAlgorithm::Md5, "MD5"),
            (HashAlgorithm::Sha1, "SHA1"),
            (HashAlgorithm::Sha224, "SHA224"),
            (HashAlgorithm::Sha256, "SHA256"),
            (HashAlgorithm::Sha384, "SHA384"),
            (HashAlgorithm::Sha512, "SHA512"),
        ] {
            assert_eq!(ha.to_attr(), *attr);
        }
    }

    #[test]
    fn test_signature_algorithm_try_from() {
        for (n, ha) in &[
            (1_u8, SignatureAlgorithm::Rsa),
            (2_u8, SignatureAlgorithm::Dsa),
            (3_u8, SignatureAlgorithm::Ecdsa),
        ] {
            let res = SignatureAlgorithm::try_from(*n).unwrap();
            assert_eq!(&res, ha);
        }

        // We don't support "anonymous" signature algorithms.
        assert!(SignatureAlgorithm::try_from(0).is_err());
        assert!(SignatureAlgorithm::try_from(4).is_err());
    }

    #[test]
    fn test_signature_algorithm_to_attr() {
        for (sa, attr) in &[
            (SignatureAlgorithm::Rsa, "RSA"),
            (SignatureAlgorithm::Dsa, "DSA"),
            (SignatureAlgorithm::Ecdsa, "ECDSA"),
        ] {
            assert_eq!(sa.to_attr(), *attr);
        }
    }
}
