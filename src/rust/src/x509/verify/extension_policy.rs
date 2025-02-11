use std::collections::HashSet;
use std::sync::Arc;

use cryptography_x509::oid::{
    AUTHORITY_INFORMATION_ACCESS_OID, AUTHORITY_KEY_IDENTIFIER_OID, BASIC_CONSTRAINTS_OID,
    EXTENDED_KEY_USAGE_OID, KEY_USAGE_OID, NAME_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID,
    SUBJECT_KEY_IDENTIFIER_OID,
};

use cryptography_x509::extensions::Extension;

use cryptography_x509_verification::ops::VerificationCertificate;
use cryptography_x509_verification::policy::{
    Criticality, ExtensionPolicy, ExtensionValidator, MaybeExtensionValidatorCallback, Policy,
    PresentExtensionValidatorCallback,
};
use cryptography_x509_verification::{ValidationError, ValidationErrorKind, ValidationResult};
use pyo3::types::PyAnyMethods;
use pyo3::types::PyTypeMethods;
use pyo3::{intern, PyResult};

use crate::asn1::py_oid_to_oid;

use crate::types;
use crate::x509::certificate::parse_cert_ext;
use crate::x509::certificate::Certificate as PyCertificate;

use super::policy::PyPolicy;
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

    fn check_duplicate_oid(&self, oid: &asn1::ObjectIdentifier) -> PyResult<()> {
        if self.already_set_oids.contains(oid) {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "ExtensionPolicy already configured for extension with OID {oid}"
            )));
        }
        Ok(())
    }

    fn with_assigned_validator(
        &self,
        oid: asn1::ObjectIdentifier,
        validator: ExtensionValidator<'static, PyCryptoOps>,
    ) -> PyResult<PyExtensionPolicy> {
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
                    "Unsupported extension OID: {}",
                    oid
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
        self.check_duplicate_oid(&oid)?;
        self.with_assigned_validator(oid, ExtensionValidator::NotPresent)
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
        self.check_duplicate_oid(&oid)?;
        self.with_assigned_validator(
            oid,
            ExtensionValidator::MaybePresent {
                criticality: criticality.into(),
                validator: validator_cb.map(make_rust_maybe_validator_cb),
            },
        )
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
        self.check_duplicate_oid(&oid)?;
        self.with_assigned_validator(
            oid,
            ExtensionValidator::Present {
                criticality: criticality.into(),
                validator: validator_cb.map(make_rust_present_validator_cb),
            },
        )
    }
}

fn make_rust_maybe_validator_cb(
    py_cb: pyo3::PyObject,
) -> MaybeExtensionValidatorCallback<'static, PyCryptoOps> {
    Arc::new(
        move |policy: &Policy<'_, PyCryptoOps>,
              cert: &VerificationCertificate<'_, PyCryptoOps>,
              ext: Option<&Extension<'_>>| {
            pyo3::Python::with_gil(|py| {
                let args = make_python_callback_args(py, policy, cert, ext)?;
                invoke_py_validator_callback(py, &py_cb, args)
            })
        },
    )
}

fn make_rust_present_validator_cb(
    py_cb: pyo3::PyObject,
) -> PresentExtensionValidatorCallback<'static, PyCryptoOps> {
    Arc::new(
        move |policy: &Policy<'_, PyCryptoOps>,
              cert: &VerificationCertificate<'_, PyCryptoOps>,
              ext: &Extension<'_>| {
            pyo3::Python::with_gil(|py| {
                let (policy, cert, ext) = make_python_callback_args(py, policy, cert, Some(ext))?;
                invoke_py_validator_callback(py, &py_cb, (policy, cert, ext.unwrap()))
            })
        },
    )
}

fn make_validation_error(msg: String) -> ValidationError<'static, PyCryptoOps> {
    ValidationError::new(ValidationErrorKind::Other(msg))
}

type PyCallbackArgs<'p> = (
    pyo3::Py<PyPolicy>,
    pyo3::Py<PyCertificate>,
    Option<pyo3::Bound<'p, pyo3::types::PyAny>>,
);

fn make_python_callback_args<'chain, 'p>(
    py: pyo3::Python<'p>,
    policy: &Policy<'_, PyCryptoOps>,
    cert: &VerificationCertificate<'chain, PyCryptoOps>,
    ext: Option<&Extension<'p>>,
) -> ValidationResult<'chain, PyCallbackArgs<'p>, PyCryptoOps> {
    let py_policy = policy.extra.clone_ref(py);
    let py_cert = cert.extra().clone_ref(py);
    let py_ext = match ext {
        None => None,
        Some(ext) => parse_cert_ext(py, ext).map_err(|e| {
            make_validation_error(format!("{e} (while converting Extension to Python object)"))
        })?,
    };

    Ok((py_policy, py_cert, py_ext))
}

fn invoke_py_validator_callback<'py>(
    py: pyo3::Python<'py>,
    py_cb: &pyo3::PyObject,
    args: impl pyo3::IntoPyObject<'py, Target = pyo3::types::PyTuple>,
) -> ValidationResult<'static, (), PyCryptoOps> {
    let result = py_cb
        .bind(py)
        .call1(args)
        .map_err(|e| make_validation_error(format!("Python extension validator failed: {}", e)))?;

    if !result.is_none() {
        Err(make_validation_error(
            "Python validator must return None.".to_string(),
        ))
    } else {
        Ok(())
    }
}
