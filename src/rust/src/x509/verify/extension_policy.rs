use std::sync::Arc;

use cryptography_x509::extensions::Extension;
use cryptography_x509_verification::ops::VerificationCertificate;
use cryptography_x509_verification::policy::{
    Criticality, ExtensionPolicy, ExtensionValidator, MaybeExtensionValidatorCallback, Policy,
    PresentExtensionValidatorCallback,
};
use cryptography_x509_verification::{ValidationError, ValidationErrorKind, ValidationResult};
use pyo3::types::{PyAnyMethods, PyTypeMethods};
use pyo3::{intern, PyResult};

use super::PyCryptoOps;
use crate::asn1::{oid_to_py_oid, py_oid_to_oid};
use crate::error::CryptographyError;
use crate::types;
use crate::x509::certificate::parse_cert_ext;

#[pyo3::pyclass(
    frozen,
    eq,
    from_py_object,
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
pub(crate) struct PyExtensionPolicy {
    inner_policy: ExtensionPolicy<'static, PyCryptoOps>,
}

impl PyExtensionPolicy {
    pub(super) fn clone_inner_policy(&self) -> ExtensionPolicy<'static, PyCryptoOps> {
        self.inner_policy.clone()
    }

    fn new(inner_policy: ExtensionPolicy<'static, PyCryptoOps>) -> Self {
        PyExtensionPolicy { inner_policy }
    }

    fn with_assigned_validator(
        &self,
        validator: ExtensionValidator<'static, PyCryptoOps>,
    ) -> PyResult<PyExtensionPolicy> {
        let inner_policy = self.inner_policy.with_validator(validator).map_err(|oid| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "ExtensionPolicy already configured for extension with OID {oid}"
            ))
        })?;
        Ok(PyExtensionPolicy { inner_policy })
    }
}

fn oid_from_py_extension_type(
    py: pyo3::Python<'_>,
    extension_type: pyo3::Bound<'_, pyo3::types::PyType>,
) -> pyo3::PyResult<asn1::ObjectIdentifier> {
    if !extension_type.is_subclass(&types::EXTENSION_TYPE.get(py)?)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "extension_type must be a subclass of ExtensionType",
        ));
    }

    py_oid_to_oid(extension_type.getattr(intern!(py, "oid"))?)
}

#[pyo3::pymethods]
impl PyExtensionPolicy {
    #[staticmethod]
    pub(crate) fn permit_all() -> Self {
        PyExtensionPolicy::new(ExtensionPolicy::new_permit_all())
    }

    #[staticmethod]
    pub(crate) fn webpki_defaults_ca() -> Self {
        PyExtensionPolicy::new(ExtensionPolicy::new_default_webpki_ca())
    }

    #[staticmethod]
    pub(crate) fn webpki_defaults_ee() -> Self {
        PyExtensionPolicy::new(ExtensionPolicy::new_default_webpki_ee())
    }

    pub(crate) fn require_not_present(
        &self,
        py: pyo3::Python<'_>,
        extension_type: pyo3::Bound<'_, pyo3::types::PyType>,
    ) -> pyo3::PyResult<PyExtensionPolicy> {
        let oid = oid_from_py_extension_type(py, extension_type)?;
        self.with_assigned_validator(ExtensionValidator::NotPresent { oid })
    }

    #[pyo3(signature = (extension_type, criticality, validator_cb))]
    pub(crate) fn may_be_present(
        &self,
        py: pyo3::Python<'_>,
        extension_type: pyo3::Bound<'_, pyo3::types::PyType>,
        criticality: PyCriticality,
        validator_cb: Option<pyo3::Py<pyo3::PyAny>>,
    ) -> pyo3::PyResult<PyExtensionPolicy> {
        let oid = oid_from_py_extension_type(py, extension_type)?;
        self.with_assigned_validator(ExtensionValidator::MaybePresent {
            oid,
            criticality: criticality.into(),
            validator: validator_cb.map(wrap_maybe_validator_callback),
        })
    }

    #[pyo3(signature = (extension_type, criticality, validator_cb))]
    pub(crate) fn require_present(
        &self,
        py: pyo3::Python<'_>,
        extension_type: pyo3::Bound<'_, pyo3::types::PyType>,
        criticality: PyCriticality,
        validator_cb: Option<pyo3::Py<pyo3::PyAny>>,
    ) -> pyo3::PyResult<PyExtensionPolicy> {
        let oid = oid_from_py_extension_type(py, extension_type)?;
        self.with_assigned_validator(ExtensionValidator::Present {
            oid,
            criticality: criticality.into(),
            validator: validator_cb.map(wrap_present_validator_callback),
        })
    }
}

fn wrap_maybe_validator_callback(
    py_cb: pyo3::Py<pyo3::PyAny>,
) -> MaybeExtensionValidatorCallback<'static, PyCryptoOps> {
    Arc::new(
        move |policy: &Policy<'_, PyCryptoOps>,
              cert: &VerificationCertificate<'_, PyCryptoOps>,
              ext: Option<&Extension<'_>>| {
            pyo3::Python::attach(|py| {
                invoke_py_validator_callback(
                    py,
                    &py_cb,
                    (
                        policy.extra.clone_ref(py),
                        cert.extra().clone_ref(py),
                        make_py_extension(py, ext)?,
                    ),
                )
            })
        },
    )
}

fn wrap_present_validator_callback(
    py_cb: pyo3::Py<pyo3::PyAny>,
) -> PresentExtensionValidatorCallback<'static, PyCryptoOps> {
    Arc::new(
        move |policy: &Policy<'_, PyCryptoOps>,
              cert: &VerificationCertificate<'_, PyCryptoOps>,
              ext: &Extension<'_>| {
            pyo3::Python::attach(|py| {
                invoke_py_validator_callback(
                    py,
                    &py_cb,
                    (
                        policy.extra.clone_ref(py),
                        cert.extra().clone_ref(py),
                        make_py_extension(py, Some(ext))?.unwrap(),
                    ),
                )
            })
        },
    )
}

fn make_py_extension<'chain, 'p>(
    py: pyo3::Python<'p>,
    ext: Option<&Extension<'p>>,
) -> ValidationResult<'chain, Option<pyo3::Bound<'p, pyo3::types::PyAny>>, PyCryptoOps> {
    let conversion_error = |e: CryptographyError| {
        ValidationError::new(ValidationErrorKind::Other(format!(
            "{e} (while converting Extension to Python object)"
        )))
    };

    Ok(match ext {
        None => None,
        Some(ext) => match parse_cert_ext(py, ext).map_err(conversion_error)? {
            Some(parsed) => Some(parsed),
            // The extension is present but its value can't be parsed into a
            // known Python object. Mirror `Certificate.extensions` and surface
            // it as an `UnrecognizedExtension` rather than dropping it to None.
            None => {
                let oid =
                    oid_to_py_oid(py, &ext.extn_id).map_err(|e| conversion_error(e.into()))?;
                let unrecognized = types::UNRECOGNIZED_EXTENSION
                    .get(py)
                    .and_then(|ty| ty.call1((oid, ext.extn_value)))
                    .map_err(|e| conversion_error(e.into()))?;
                Some(unrecognized)
            }
        },
    })
}

fn invoke_py_validator_callback<'py>(
    py: pyo3::Python<'py>,
    py_cb: &pyo3::Py<pyo3::PyAny>,
    args: impl pyo3::call::PyCallArgs<'py>,
) -> ValidationResult<'static, (), PyCryptoOps> {
    let result = py_cb.bind(py).call1(args).map_err(|e| {
        ValidationError::new(ValidationErrorKind::Other(format!(
            "Python extension validator failed: {e}",
        )))
    })?;

    if !result.is_none() {
        let error_kind =
            ValidationErrorKind::Other("Python validator must return None.".to_string());
        Err(ValidationError::new(error_kind))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cryptography_x509::extensions::Extension;

    #[test]
    fn test_make_py_extension_fail() {
        pyo3::Python::attach(|py| {
            let invalid_extension = Extension {
                // SubjectAlternativeName
                extn_id: asn1::ObjectIdentifier::from_string("2.5.29.17").unwrap(),
                critical: false,
                extn_value: &[],
            };
            let result = super::make_py_extension(py, Some(&invalid_extension));
            assert!(result.is_err());
            let error = result.unwrap_err();
            assert!(format!("{error}").contains("(while converting Extension to Python object)"));
        })
    }
}
