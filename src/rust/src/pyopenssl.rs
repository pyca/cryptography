// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Python adapters for owned OpenSSL compatibility objects.
#![forbid(unsafe_code)]
use openssl_bridge::{hash::Algorithm, x509, Error};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::{Mutex, MutexGuard};
mod tls;

pyo3::create_exception!(pyopenssl, NativeError, pyo3::exceptions::PyException);
pyo3::create_exception!(pyopenssl, VerificationError, pyo3::exceptions::PyException);

fn bridge_error(error: Error) -> PyErr {
    match error {
        Error::InvalidInput(message)
        | Error::Unsupported(message)
        | Error::InvalidState(message) => pyo3::exceptions::PyValueError::new_err(message),
        Error::Native(errors) => NativeError::new_err(
            errors
                .into_iter()
                .map(|e| {
                    let library = e.description.split(':').nth(2).unwrap_or("").to_owned();
                    (library, String::new(), e.reason_text)
                })
                .collect::<Vec<_>>(),
        ),
        // Required for a non-exhaustive dependency enum; all current variants
        // are handled above, so this arm cannot be constructed in this version.
        // NO-COVERAGE-START
        _ => NativeError::new_err(error.to_string()),
        // NO-COVERAGE-END
    }
}

fn lock<T>(object: &Mutex<T>) -> PyResult<MutexGuard<'_, T>> {
    object
        .lock()
        .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("native object lock is poisoned"))
}
fn encoding(value: u32) -> PyResult<x509::Encoding> {
    match value {
        1 => Ok(x509::Encoding::Pem),
        2 => Ok(x509::Encoding::Der),
        65535 => Ok(x509::Encoding::Text),
        _ => Err(pyo3::exceptions::PyValueError::new_err("invalid encoding")),
    }
}
fn name_field(issuer: bool) -> x509::NameField {
    if issuer {
        x509::NameField::Issuer
    } else {
        x509::NameField::Subject
    }
}
fn time_field(after: bool) -> x509::TimeField {
    if after {
        x509::TimeField::NotAfter
    } else {
        x509::TimeField::NotBefore
    }
}

// PyO3 generates fallible type-registration machinery for this declaration.
// NO-COVERAGE-START
#[pyclass(module = "cryptography.hazmat.bindings._rust.pyopenssl", name = "Name")]
// NO-COVERAGE-END
struct PyName {
    inner: Mutex<x509::Name>,
}
#[pymethods]
impl PyName {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(Self {
            inner: Mutex::new(x509::Name::empty().map_err(bridge_error)?),
        })
    }
    #[staticmethod]
    fn from_der(der: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: Mutex::new(x509::Name::from_der(der).map_err(bridge_error)?),
        })
    }
    fn copy(&self) -> PyResult<Self> {
        Ok(Self {
            inner: Mutex::new(lock(&self.inner)?.try_clone().map_err(bridge_error)?),
        })
    }
    fn der<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyBytes>> {
        Ok(PyBytes::new(
            py,
            &lock(&self.inner)?.der().map_err(bridge_error)?,
        ))
    }
    fn set(&self, attribute: &[u8], value: &[u8]) -> PyResult<()> {
        let attribute = x509::c_string(attribute).map_err(bridge_error)?;
        lock(&self.inner)?
            .set(&attribute, value)
            .map_err(bridge_error)
    }
    fn get(&self, attribute: &[u8]) -> PyResult<Option<String>> {
        let attribute = x509::c_string(attribute).map_err(bridge_error)?;
        lock(&self.inner)?.get(&attribute).map_err(bridge_error)
    }
    fn components<'p>(
        &self,
        py: Python<'p>,
    ) -> PyResult<Vec<(Bound<'p, PyBytes>, Bound<'p, PyBytes>)>> {
        Ok(lock(&self.inner)?
            .components()
            .map_err(bridge_error)?
            .into_iter()
            .map(|(name, value)| (PyBytes::new(py, &name), PyBytes::new(py, &value)))
            .collect())
    }
    fn compare(&self, other: &Self) -> PyResult<i32> {
        // Copy before taking the second lock, including for self-comparison.
        let mut other = lock(&other.inner)?.try_clone().map_err(bridge_error)?;
        Ok(match lock(&self.inner)?.compare(&mut other) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        })
    }
    fn hash(&self) -> PyResult<u64> {
        Ok(lock(&self.inner)?.hash())
    }
    fn display(&self) -> PyResult<String> {
        lock(&self.inner)?.display().map_err(bridge_error)
    }
}

// PyO3 generates fallible type-registration machinery for this declaration.
// NO-COVERAGE-START
#[pyclass(
    module = "cryptography.hazmat.bindings._rust.pyopenssl",
    name = "Certificate"
)]
// NO-COVERAGE-END
struct PyCertificate {
    inner: Mutex<x509::Certificate>,
}
#[pymethods]
impl PyCertificate {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(Self {
            inner: Mutex::new(x509::Certificate::empty().map_err(bridge_error)?),
        })
    }
    #[staticmethod]
    fn decode(data: &[u8], format: u32) -> PyResult<Self> {
        Ok(Self {
            inner: Mutex::new(
                x509::Certificate::decode(data, encoding(format)?).map_err(bridge_error)?,
            ),
        })
    }
    fn encode<'p>(&self, py: Python<'p>, format: u32) -> PyResult<Bound<'p, PyBytes>> {
        Ok(PyBytes::new(
            py,
            &lock(&self.inner)?
                .encode(encoding(format)?)
                .map_err(bridge_error)?,
        ))
    }
    fn version(&self) -> PyResult<i64> {
        Ok(lock(&self.inner)?.version())
    }
    fn set_version(&self, version: i64) -> PyResult<()> {
        lock(&self.inner)?
            .set_version(version)
            .map_err(bridge_error)
    }
    fn name(&self, issuer: bool) -> PyResult<PyName> {
        Ok(PyName {
            inner: Mutex::new(
                lock(&self.inner)?
                    .name(name_field(issuer))
                    .map_err(bridge_error)?,
            ),
        })
    }
    fn set_name(&self, issuer: bool, name: &PyName) -> PyResult<()> {
        let mut name = lock(&name.inner)?.try_clone().map_err(bridge_error)?;
        lock(&self.inner)?
            .set_name(name_field(issuer), &mut name)
            .map_err(bridge_error)
    }
    fn set_name_attribute(&self, issuer: bool, attribute: &[u8], value: &[u8]) -> PyResult<()> {
        let attribute = x509::c_string(attribute).map_err(bridge_error)?;
        let mut cert = lock(&self.inner)?;
        let mut name = cert.name(name_field(issuer)).map_err(bridge_error)?;
        name.set(&attribute, value).map_err(bridge_error)?;
        cert.set_name(name_field(issuer), &mut name)
            .map_err(bridge_error)
    }
    fn public_key_der<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyBytes>> {
        Ok(PyBytes::new(
            py,
            &lock(&self.inner)?.public_key_der().map_err(bridge_error)?,
        ))
    }
    fn set_public_key_der(&self, der: &[u8]) -> PyResult<()> {
        lock(&self.inner)?
            .set_public_key_der(der)
            .map_err(bridge_error)
    }
    fn sign(&self, der: &[u8], digest: &str) -> PyResult<()> {
        lock(&self.inner)?
            .sign(der, Algorithm::from_name(digest).map_err(bridge_error)?)
            .map_err(bridge_error)
    }
    fn signature_algorithm<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyBytes>> {
        Ok(PyBytes::new(
            py,
            &lock(&self.inner)?
                .signature_algorithm()
                .map_err(bridge_error)?,
        ))
    }
    fn digest<'p>(&self, py: Python<'p>, digest: &str) -> PyResult<Bound<'p, PyBytes>> {
        Ok(PyBytes::new(
            py,
            &lock(&self.inner)?
                .digest(Algorithm::from_name(digest).map_err(bridge_error)?)
                .map_err(bridge_error)?,
        ))
    }
    fn serial<'p>(&self, py: Python<'p>) -> PyResult<(bool, Bound<'p, PyBytes>)> {
        let (negative, magnitude) = lock(&self.inner)?.serial().map_err(bridge_error)?;
        Ok((negative, PyBytes::new(py, &magnitude)))
    }
    fn set_serial(&self, value: &[u8]) -> PyResult<()> {
        lock(&self.inner)?.set_serial(value).map_err(bridge_error)
    }
    fn time<'p>(&self, py: Python<'p>, after: bool) -> PyResult<Option<Bound<'p, PyBytes>>> {
        Ok(lock(&self.inner)?
            .time(time_field(after))
            .map_err(bridge_error)?
            .map(|data| PyBytes::new(py, &data)))
    }
    fn set_time(&self, after: bool, time: &[u8]) -> PyResult<()> {
        let time = x509::c_string(time).map_err(bridge_error)?;
        lock(&self.inner)?
            .set_time(time_field(after), &time)
            .map_err(bridge_error)
    }
    fn adjust_time(&self, after: bool, seconds: i64) -> PyResult<()> {
        lock(&self.inner)?
            .adjust_time(time_field(after), seconds)
            .map_err(bridge_error)
    }
    fn extension_count(&self) -> PyResult<usize> {
        Ok(lock(&self.inner)?.extension_count())
    }
}

// PyO3 generates fallible type-registration machinery for this declaration.
// NO-COVERAGE-START
#[pyclass(
    module = "cryptography.hazmat.bindings._rust.pyopenssl",
    name = "TrustStore"
)]
// NO-COVERAGE-END
struct PyTrustStore {
    inner: Mutex<x509::TrustStore>,
}
#[pymethods]
impl PyTrustStore {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(Self {
            inner: Mutex::new(x509::TrustStore::new().map_err(bridge_error)?),
        })
    }
    fn add_certificate_der(&self, der: &[u8]) -> PyResult<()> {
        lock(&self.inner)?
            .add_certificate_der(der)
            .map_err(bridge_error)
    }
    fn add_crl_der(&self, der: &[u8]) -> PyResult<()> {
        lock(&self.inner)?.add_crl_der(der).map_err(bridge_error)
    }
    fn set_flags(&self, flags: u64) -> PyResult<()> {
        lock(&self.inner)?.set_flags(flags).map_err(bridge_error)
    }
    fn set_time(&self, time: i64) -> PyResult<()> {
        lock(&self.inner)?.set_time(time).map_err(bridge_error)
    }
    #[pyo3(signature = (file=None, directory=None))]
    fn load_locations(&self, file: Option<&[u8]>, directory: Option<&[u8]>) -> PyResult<()> {
        let file = file.map(x509::c_string).transpose().map_err(bridge_error)?;
        let directory = directory
            .map(x509::c_string)
            .transpose()
            .map_err(bridge_error)?;
        lock(&self.inner)?
            .load_locations(file.as_deref(), directory.as_deref())
            .map_err(bridge_error)
    }
    fn verify<'p>(
        &self,
        py: Python<'p>,
        leaf: &[u8],
        chain: Vec<Vec<u8>>,
    ) -> PyResult<Vec<Bound<'p, PyBytes>>> {
        match lock(&self.inner)?.verify(leaf, &chain) {
            Ok(chain) => Ok(chain
                .into_iter()
                .map(|der| PyBytes::new(py, &der))
                .collect()),
            Err(x509::VerificationError::Backend(error)) => Err(bridge_error(error)),
            Err(x509::VerificationError::Untrusted(error)) => Err(VerificationError::new_err((
                error.code,
                error.depth,
                error.message,
                error
                    .certificate_der
                    .map(|der| PyBytes::new(py, &der).unbind()),
            ))),
        }
    }
}

#[pyfunction]
fn random_mix(input: &[u8]) -> PyResult<()> {
    openssl_bridge::rand::mix_additional_input(input).map_err(bridge_error)
}
#[pyfunction]
fn random_ready() -> PyResult<bool> {
    openssl_bridge::rand::is_ready().map_err(bridge_error)
}
#[pyfunction]
fn compiled_version_text() -> String {
    openssl_bridge::runtime::compiled_version_text()
}

#[pymodule(gil_used = false)]
pub(crate) fn pyopenssl(module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    tls::register(module)?;
    module.add_function(wrap_pyfunction!(random_mix, module)?)?;
    module.add_function(wrap_pyfunction!(random_ready, module)?)?;
    module.add_function(wrap_pyfunction!(compiled_version_text, module)?)?;
    for (name, value) in x509::compatibility_constants() {
        module.add(name, value)?;
    }
    module.add_function(wrap_pyfunction!(curve_names, module)?)?;
    module.add_function(wrap_pyfunction!(legacy_dsa_private_key_der, module)?)?;
    module.add_function(wrap_pyfunction!(private_key_pem, module)?)?;
    module.add_function(wrap_pyfunction!(rsa_private_key_text, module)?)?;
    module.add_class::<PyName>()?;
    module.add_class::<PyCertificate>()?;
    module.add_class::<PyTrustStore>()?;
    module.add("NativeError", module.py().get_type::<NativeError>())?;
    module.add(
        "VerificationError",
        module.py().get_type::<VerificationError>(),
    )?;
    Ok(())
}

#[pyfunction]
fn curve_names() -> PyResult<Vec<String>> {
    openssl_bridge::legacy_key::curve_names().map_err(bridge_error)
}

#[pyfunction]
fn legacy_dsa_private_key_der(py: Python<'_>, bits: u32) -> PyResult<Bound<'_, PyBytes>> {
    let der = openssl_bridge::legacy_key::dsa_private_key_der(bits).map_err(bridge_error)?;
    Ok(PyBytes::new(py, der.as_ref()))
}

#[pyfunction]
#[pyo3(signature = (der, cipher=None, password=None))]
fn private_key_pem<'p>(
    py: Python<'p>,
    der: &[u8],
    cipher: Option<&[u8]>,
    password: Option<&[u8]>,
) -> PyResult<Bound<'p, PyBytes>> {
    let cipher = cipher
        .map(x509::c_string)
        .transpose()
        .map_err(bridge_error)?;
    let pem = openssl_bridge::legacy_key::private_key_pem(der, cipher.as_deref(), password)
        .map_err(bridge_error)?;
    Ok(PyBytes::new(py, pem.as_ref()))
}

#[pyfunction]
fn rsa_private_key_text<'p>(py: Python<'p>, der: &[u8]) -> PyResult<Bound<'p, PyBytes>> {
    let text = openssl_bridge::legacy_key::rsa_private_key_text(der).map_err(bridge_error)?;
    Ok(PyBytes::new(py, text.as_ref()))
}
