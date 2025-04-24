use std::collections::HashSet;
use std::sync::Arc;

use cryptography_x509::extensions::Extension;
use cryptography_x509::oid::{
    AUTHORITY_INFORMATION_ACCESS_OID, AUTHORITY_KEY_IDENTIFIER_OID, BASIC_CONSTRAINTS_OID,
    EXTENDED_KEY_USAGE_OID, KEY_USAGE_OID, NAME_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID,
    SUBJECT_KEY_IDENTIFIER_OID,
};
use cryptography_x509_verification::ops::VerificationCertificate;
use cryptography_x509_verification::policy::{
    Criticality, ExtensionPolicy, ExtensionValidator, MaybeExtensionValidatorCallback, Policy,
    PresentExtensionValidatorCallback,
};
use cryptography_x509_verification::{ValidationError, ValidationErrorKind, ValidationResult};
use pyo3::types::{PyAnyMethods, PyTypeMethods};
use pyo3::{intern, PyResult};

use super::PyCryptoOps;
use crate::asn1::py_oid_to_oid;
use crate::types;
use crate::x509::certificate::parse_cert_ext;

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
pub(crate) struct PyExtensionPolicy {
    inner_policy: ExtensionPolicy<'static, PyCryptoOps>,
    already_set_oids: HashSet<asn1::ObjectIdentifier>,
}

impl PyExtensionPolicy {
    pub(super) fn clone_inner_policy(&self) -> ExtensionPolicy<'static, PyCryptoOps> {
        self.inner_policy.clone()
    }

    fn new(inner_policy: ExtensionPolicy<'static, PyCryptoOps>) -> Self {
        PyExtensionPolicy {
            inner_policy,
            already_set_oids: HashSet::new(),
        }
    }

    fn with_assigned_validator(
        &self,
        validator: ExtensionValidator<'static, PyCryptoOps>,
    ) -> PyResult<PyExtensionPolicy> {
        let oid = match &validator {
            ExtensionValidator::NotPresent { oid } => oid,
            ExtensionValidator::MaybePresent { oid, .. } => oid,
            ExtensionValidator::Present { oid, .. } => oid,
        }
        .clone();
        if self.already_set_oids.contains(&oid) {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "ExtensionPolicy already configured for extension with OID {oid}"
            )));
        }

        let mut policy = self.inner_policy.clone();
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
                    "Unsupported extension OID: {oid}",
                )))
            }
        }

        let mut already_set_oids = self.already_set_oids.clone();
        already_set_oids.insert(oid);
        Ok(PyExtensionPolicy {
            inner_policy: policy,
            already_set_oids,
        })
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
        validator_cb: Option<pyo3::PyObject>,
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
        validator_cb: Option<pyo3::PyObject>,
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
    py_cb: pyo3::PyObject,
) -> MaybeExtensionValidatorCallback<'static, PyCryptoOps> {
    Arc::new(
        move |policy: &Policy<'_, PyCryptoOps>,
              cert: &VerificationCertificate<'_, PyCryptoOps>,
              ext: Option<&Extension<'_>>| {
            pyo3::Python::with_gil(|py| {
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
    py_cb: pyo3::PyObject,
) -> PresentExtensionValidatorCallback<'static, PyCryptoOps> {
    Arc::new(
        move |policy: &Policy<'_, PyCryptoOps>,
              cert: &VerificationCertificate<'_, PyCryptoOps>,
              ext: &Extension<'_>| {
            pyo3::Python::with_gil(|py| {
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
    Ok(match ext {
        None => None,
        Some(ext) => parse_cert_ext(py, ext).map_err(|e| {
            ValidationError::new(ValidationErrorKind::Other(format!(
                "{e} (while converting Extension to Python object)"
            )))
        })?,
    })
}

fn invoke_py_validator_callback<'py>(
    py: pyo3::Python<'py>,
    py_cb: &pyo3::PyObject,
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
        pyo3::Python::with_gil(|py| {
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
