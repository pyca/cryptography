use std::sync::Arc;

use cryptography_x509::oid::{
    AUTHORITY_INFORMATION_ACCESS_OID, AUTHORITY_KEY_IDENTIFIER_OID, BASIC_CONSTRAINTS_OID,
    EXTENDED_KEY_USAGE_OID, KEY_USAGE_OID, NAME_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID,
    SUBJECT_KEY_IDENTIFIER_OID,
};

use cryptography_x509::{certificate::Certificate, extensions::Extension};

use cryptography_x509_verification::policy::{
    Criticality, ExtensionPolicy, ExtensionValidator, MaybeExtensionValidatorCallback, Policy,
    PresentExtensionValidatorCallback,
};
use cryptography_x509_verification::ValidationError;
use pyo3::types::PyAnyMethods;
use pyo3::PyResult;

use crate::asn1::py_oid_to_oid;

use crate::error::CryptographyResult;
use crate::x509::certificate::Certificate as PyCertificate;
use crate::x509::certificate::{parse_cert_ext, OwnedCertificate};

use super::py_policy::PyPolicy;
use super::PyCryptoOps;

#[pyo3::pyclass(
    frozen,
    eq,
    module = "cryptography.x509.verification",
    name = "Criticality"
)]
#[derive(PartialEq, Eq, Clone)]
pub(crate) enum PyCriticality {
    #[pyo3(name = "CRITICAL")]
    Critical,
    #[pyo3(name = "AGNOSTIC")]
    Agnostic,
    #[pyo3(name = "NON_CRITICAL")]
    NonCritical,
}

impl From<PyCriticality> for Criticality {
    fn from(criticality: PyCriticality) -> Criticality {
        match criticality {
            PyCriticality::Critical => Criticality::Critical,
            PyCriticality::Agnostic => Criticality::Agnostic,
            PyCriticality::NonCritical => Criticality::NonCritical,
        }
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.x509.verification",
    name = "ExtensionPolicy"
)]
pub(crate) struct PyExtensionPolicy(pub(super) ExtensionPolicy<'static, PyCryptoOps>);

impl PyExtensionPolicy {
    fn with_assigned_validator(
        &self,
        oid: pyo3::Bound<'_, pyo3::types::PyAny>,
        validator: ExtensionValidator<'static, PyCryptoOps>,
    ) -> PyResult<PyExtensionPolicy> {
        let oid = py_oid_to_oid(oid)?;
        let mut policy = self.0.clone();
        match oid {
            AUTHORITY_INFORMATION_ACCESS_OID => policy.authority_information_access = validator,
            AUTHORITY_KEY_IDENTIFIER_OID => policy.authority_key_identifier = validator,
            SUBJECT_KEY_IDENTIFIER_OID => policy.subject_key_identifier = validator,
            KEY_USAGE_OID => policy.key_usage = validator,
            SUBJECT_ALTERNATIVE_NAME_OID => policy.subject_alternative_name = validator,
            BASIC_CONSTRAINTS_OID => policy.basic_constraints = validator,
            NAME_CONSTRAINTS_OID => policy.name_constraints = validator,
            EXTENDED_KEY_USAGE_OID => policy.extended_key_usage = validator,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Unsupported extension OID: {}",
                    oid
                )))
            }
        }
        Ok(PyExtensionPolicy(policy))
    }
}

#[pyo3::pymethods]
impl PyExtensionPolicy {
    #[staticmethod]
    pub(crate) fn permit_all() -> Self {
        PyExtensionPolicy(ExtensionPolicy::new_permit_all())
    }

    #[staticmethod]
    pub(crate) fn webpki_defaults_ca() -> Self {
        PyExtensionPolicy(ExtensionPolicy::new_default_webpki_ca())
    }

    #[staticmethod]
    pub(crate) fn webpki_defaults_ee() -> Self {
        PyExtensionPolicy(ExtensionPolicy::new_default_webpki_ee())
    }

    pub(crate) fn require_not_present(
        &self,
        oid: pyo3::Bound<'_, pyo3::types::PyAny>,
    ) -> pyo3::PyResult<PyExtensionPolicy> {
        self.with_assigned_validator(oid, ExtensionValidator::<'static, PyCryptoOps>::NotPresent)
    }

    #[pyo3(signature = (oid, criticality, validator_cb))]
    pub(crate) fn may_be_present(
        &self,
        oid: pyo3::Bound<'_, pyo3::types::PyAny>,
        criticality: PyCriticality,
        validator_cb: Option<pyo3::PyObject>,
    ) -> pyo3::PyResult<PyExtensionPolicy> {
        self.with_assigned_validator(oid, make_rust_maybe_validator(criticality, validator_cb))
    }

    #[pyo3(signature = (oid, criticality, validator_cb))]
    pub(crate) fn require_present(
        &self,
        oid: pyo3::Bound<'_, pyo3::types::PyAny>,
        criticality: PyCriticality,
        validator_cb: Option<pyo3::PyObject>,
    ) -> pyo3::PyResult<PyExtensionPolicy> {
        self.with_assigned_validator(oid, make_rust_present_validator(criticality, validator_cb))
    }
}

fn cert_to_py_cert(
    py: pyo3::Python<'_>,
    cert: &Certificate<'_>,
) -> CryptographyResult<PyCertificate> {
    // TODO: can this be done better?..
    let data = asn1::write_single(cert)?;
    let owned_cert = OwnedCertificate::try_new(
        pyo3::types::PyBytes::new_bound(py, data.as_slice())
            .as_unbound()
            .clone_ref(py),
        |bytes| asn1::parse_single(bytes.as_bytes(py)),
    )?;
    Ok(PyCertificate {
        raw: owned_cert,
        cached_extensions: pyo3::sync::GILOnceCell::new(),
    })
}

fn make_python_callback_args<'p>(
    py: pyo3::Python<'p>,
    policy: &Policy<'_, PyCryptoOps>,
    cert: &Certificate<'_>,
    ext: Option<&Extension<'_>>,
) -> Result<
    (
        PyPolicy,
        PyCertificate,
        Option<pyo3::Bound<'p, pyo3::types::PyAny>>,
    ),
    ValidationError,
> {
    let py_policy = PyPolicy::from_rust_policy(py, policy).map_err(|e| {
        ValidationError::Other(format!("{e} (while converting Policy object to python)"))
    })?;
    let py_cert = cert_to_py_cert(py, cert).map_err(|e| {
        ValidationError::Other(format!(
            "{e} (while converting to python certificate object)"
        ))
    })?;
    let py_ext = match ext {
        None => None,
        Some(ext) => parse_cert_ext(py, ext).map_err(|e| {
            ValidationError::Other(format!(
                "{} (while converting to python extension object)",
                Into::<pyo3::PyErr>::into(e)
            ))
        })?,
    };

    Ok((py_policy, py_cert, py_ext))
}

fn invoke_py_validator_callback(
    py: pyo3::Python<'_>,
    py_cb: &pyo3::PyObject,
    args: impl pyo3::IntoPy<pyo3::Py<pyo3::types::PyTuple>>,
) -> Result<(), ValidationError> {
    let result = py_cb
        .bind(py)
        .call1(args)
        .map_err(|e| ValidationError::Other(format!("Python extension validator failed: {}", e)))?;

    if !result.is_none() {
        Err(ValidationError::Other(
            "Python validator must return None.".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn make_rust_maybe_validator(
    criticality: PyCriticality,
    validator: Option<pyo3::PyObject>,
) -> ExtensionValidator<'static, PyCryptoOps> {
    fn make_rust_callback<'a>(
        py_cb: pyo3::PyObject,
    ) -> MaybeExtensionValidatorCallback<'a, PyCryptoOps> {
        Arc::new(
            move |policy: &Policy<'_, PyCryptoOps>,
                  cert: &Certificate<'_>,
                  ext: Option<&Extension<'_>>|
                  -> Result<(), ValidationError> {
                pyo3::Python::with_gil(|py| -> Result<(), ValidationError> {
                    let args = make_python_callback_args(py, policy, cert, ext)?;
                    invoke_py_validator_callback(py, &py_cb, args)
                })
            },
        )
    }
    ExtensionValidator::MaybePresent {
        criticality: criticality.into(),
        validator: match validator {
            None => None,
            Some(py_cb) => Some(make_rust_callback(py_cb)),
        },
    }
}

fn make_rust_present_validator(
    criticality: PyCriticality,
    validator: Option<pyo3::PyObject>,
) -> ExtensionValidator<'static, PyCryptoOps> {
    fn make_rust_callback<'a>(
        py_cb: pyo3::PyObject,
    ) -> PresentExtensionValidatorCallback<'a, PyCryptoOps> {
        Arc::new(
            move |policy: &Policy<'_, PyCryptoOps>,
                  cert: &Certificate<'_>,
                  ext: &Extension<'_>|
                  -> Result<(), ValidationError> {
                pyo3::Python::with_gil(|py| -> Result<(), ValidationError> {
                    let args = make_python_callback_args(py, policy, cert, Some(ext))?;
                    let args = (args.0, args.1, args.2.unwrap());

                    invoke_py_validator_callback(py, &py_cb, args)
                })
            },
        )
    }

    ExtensionValidator::Present {
        criticality: criticality.into(),
        validator: match validator {
            None => None,
            Some(py_cb) => Some(make_rust_callback(py_cb)),
        },
    }
}
