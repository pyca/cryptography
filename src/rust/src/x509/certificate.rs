// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use cryptography_x509::certificate::Certificate as RawCertificate;
use cryptography_x509::common::{AlgorithmParameters, Asn1Read, Asn1ReadableOrWritable};
use cryptography_x509::extensions::{
    Admission, Admissions, AuthorityKeyIdentifier, BasicConstraints, DisplayText,
    DistributionPoint, DistributionPointName, DuplicateExtensionsError, ExtendedKeyUsage,
    Extension, IssuerAlternativeName, KeyUsage, MSCertificateTemplate, NameConstraints,
    NamingAuthority, PolicyConstraints, PolicyInformation, PolicyQualifierInfo, ProfessionInfo,
    Qualifier, RawExtensions, SequenceOfAccessDescriptions, SequenceOfSubtrees,
    SubjectAlternativeName, UserNotice,
};
use cryptography_x509::{common, oid};
use cryptography_x509_verification::ops::CryptoOps;
use pyo3::types::{PyAnyMethods, PyListMethods};

use crate::asn1::{
    big_byte_slice_to_py_int, encode_der_data, oid_to_py_oid, py_uint_to_big_endian_bytes,
};
use crate::backend::{hashes, keys};
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509::common::cstr_from_literal;
use crate::x509::verify::PyCryptoOps;
use crate::x509::{extensions, sct, sign};
use crate::{exceptions, types, x509};

self_cell::self_cell!(
    pub(crate) struct OwnedCertificate {
        owner: pyo3::Py<pyo3::types::PyBytes>,

        #[covariant]
        dependent: RawCertificate,
    }
);

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.x509")]
pub(crate) struct Certificate {
    pub(crate) raw: OwnedCertificate,
    pub(crate) cached_extensions: pyo3::sync::GILOnceCell<pyo3::PyObject>,
}

#[pyo3::pymethods]
impl Certificate {
    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.raw.borrow_dependent().hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Certificate>) -> bool {
        self.raw.borrow_dependent() == other.raw.borrow_dependent()
    }

    fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        let subject = self.subject(py)?;
        let subject_repr = subject.repr()?.extract::<pyo3::pybacked::PyBackedStr>()?;
        Ok(format!("<Certificate(subject={subject_repr}, ...)>"))
    }

    fn __deepcopy__(slf: pyo3::PyRef<'_, Self>, _memo: pyo3::PyObject) -> pyo3::PyRef<'_, Self> {
        slf
    }

    pub(crate) fn public_key<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        keys::load_der_public_key_bytes(
            py,
            self.raw.borrow_dependent().tbs_cert.spki.tlv().full_data(),
        )
    }

    #[getter]
    fn public_key_algorithm_oid<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        oid_to_py_oid(
            py,
            self.raw.borrow_dependent().tbs_cert.spki.algorithm.oid(),
        )
    }

    pub(crate) fn fingerprint<'p>(
        &self,
        py: pyo3::Python<'p>,
        algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let serialized = asn1::write_single(self.raw.borrow_dependent())?;

        let mut h = hashes::Hash::new(py, algorithm, None)?;
        h.update_bytes(&serialized)?;
        h.finalize(py)
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let result = asn1::write_single(self.raw.borrow_dependent())?;

        encode_der_data(py, "CERTIFICATE".to_string(), result, encoding)
    }

    #[getter]
    fn serial_number<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<pyo3::Bound<'p, pyo3::PyAny>, CryptographyError> {
        let bytes = self.raw.borrow_dependent().tbs_cert.serial.as_bytes();
        warn_if_negative_serial(py, bytes)?;
        Ok(big_byte_slice_to_py_int(py, bytes)?)
    }

    #[getter]
    fn version<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<pyo3::Bound<'p, pyo3::PyAny>, CryptographyError> {
        let version = &self.raw.borrow_dependent().tbs_cert.version;
        cert_version(py, *version)
    }

    #[getter]
    fn issuer<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        Ok(x509::parse_name(py, self.raw.borrow_dependent().issuer())
            .map_err(|e| e.add_location(asn1::ParseLocation::Field("issuer")))?)
    }

    #[getter]
    fn subject<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        Ok(x509::parse_name(py, self.raw.borrow_dependent().subject())
            .map_err(|e| e.add_location(asn1::ParseLocation::Field("subject")))?)
    }

    #[getter]
    fn tbs_certificate_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let result = asn1::write_single(&self.raw.borrow_dependent().tbs_cert)?;
        Ok(pyo3::types::PyBytes::new(py, &result))
    }

    #[getter]
    fn tbs_precertificate_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let val = self.raw.borrow_dependent();
        let mut tbs_precert = val.tbs_cert.clone();
        // Remove the SCT list extension
        match val.extensions() {
            Ok(extensions) => {
                let ext_count = extensions
                    .as_raw()
                    .as_ref()
                    .map_or(0, |raw| raw.unwrap_read().len());
                let filtered_extensions: Vec<Extension<'_>> = extensions
                    .iter()
                    .filter(|x| x.extn_id != oid::PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID)
                    .collect();
                if filtered_extensions.len() == ext_count {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "Could not find pre-certificate SCT list extension",
                        ),
                    ));
                }
                let filtered_extensions: RawExtensions<'_> = Asn1ReadableOrWritable::new_write(
                    asn1::SequenceOfWriter::new(filtered_extensions),
                );

                tbs_precert.raw_extensions = Some(filtered_extensions);
                let result = asn1::write_single(&tbs_precert)?;
                Ok(pyo3::types::PyBytes::new(py, &result))
            }
            Err(DuplicateExtensionsError(oid)) => {
                let oid_obj = oid_to_py_oid(py, &oid)?;
                Err(exceptions::DuplicateExtension::new_err((
                    format!("Duplicate {} extension found", &oid),
                    oid_obj.unbind(),
                ))
                .into())
            }
        }
    }

    #[getter]
    fn signature<'p>(&self, py: pyo3::Python<'p>) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, self.raw.borrow_dependent().signature.as_bytes())
    }

    #[getter]
    fn not_valid_before<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_42.get(py)?;
        let message = cstr_from_literal!("Properties that return a naïve datetime object have been deprecated. Please switch to not_valid_before_utc.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        let dt = &self
            .raw
            .borrow_dependent()
            .tbs_cert
            .validity
            .not_before
            .as_datetime();
        x509::datetime_to_py(py, dt)
    }

    #[getter]
    fn not_valid_before_utc<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let dt = &self
            .raw
            .borrow_dependent()
            .tbs_cert
            .validity
            .not_before
            .as_datetime();
        x509::datetime_to_py_utc(py, dt)
    }

    #[getter]
    fn not_valid_after<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_42.get(py)?;
        let message = cstr_from_literal!("Properties that return a naïve datetime object have been deprecated. Please switch to not_valid_after_utc.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        let dt = &self
            .raw
            .borrow_dependent()
            .tbs_cert
            .validity
            .not_after
            .as_datetime();
        x509::datetime_to_py(py, dt)
    }

    #[getter]
    fn not_valid_after_utc<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let dt = &self
            .raw
            .borrow_dependent()
            .tbs_cert
            .validity
            .not_after
            .as_datetime();
        x509::datetime_to_py_utc(py, dt)
    }

    #[getter]
    fn signature_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<pyo3::Bound<'p, pyo3::PyAny>, CryptographyError> {
        sign::identify_signature_hash_algorithm(py, &self.raw.borrow_dependent().signature_alg)
    }

    #[getter]
    fn signature_algorithm_oid<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        oid_to_py_oid(py, self.raw.borrow_dependent().signature_alg.oid())
    }

    #[getter]
    fn signature_algorithm_parameters<'p>(
        &'p self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        sign::identify_signature_algorithm_parameters(
            py,
            &self.raw.borrow_dependent().signature_alg,
        )
    }

    #[getter]
    fn extensions(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        x509::parse_and_cache_extensions(
            py,
            &self.cached_extensions,
            &self.raw.borrow_dependent().tbs_cert.raw_extensions,
            |ext| match ext.extn_id {
                oid::PRECERT_POISON_OID => {
                    ext.value::<()>()?;
                    Ok(Some(types::PRECERT_POISON.get(py)?.call0()?))
                }
                oid::PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID => {
                    let contents = ext.value::<&[u8]>()?;
                    let scts = sct::parse_scts(py, contents, sct::LogEntryType::PreCertificate)?;
                    Ok(Some(
                        types::PRECERTIFICATE_SIGNED_CERTIFICATE_TIMESTAMPS
                            .get(py)?
                            .call1((scts,))?,
                    ))
                }
                _ => parse_cert_ext(py, ext),
            },
        )
    }

    fn verify_directly_issued_by(
        &self,
        issuer: pyo3::PyRef<'_, Certificate>,
    ) -> CryptographyResult<()> {
        if self.raw.borrow_dependent().tbs_cert.signature_alg
            != self.raw.borrow_dependent().signature_alg
        {
            return Err(CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                "Inner and outer signature algorithms do not match. This is an invalid certificate."
            )));
        };
        if self.raw.borrow_dependent().tbs_cert.issuer
            != issuer.raw.borrow_dependent().tbs_cert.subject
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Issuer certificate subject does not match certificate issuer.",
                ),
            ));
        };

        let ops = PyCryptoOps {};
        let issuer_key = ops.public_key(issuer.raw.borrow_dependent())?;
        ops.verify_signed_by(self.raw.borrow_dependent(), &issuer_key)
    }
}

fn cert_version(
    py: pyo3::Python<'_>,
    version: u8,
) -> Result<pyo3::Bound<'_, pyo3::PyAny>, CryptographyError> {
    match version {
        0 => Ok(types::CERTIFICATE_VERSION_V1.get(py)?),
        2 => Ok(types::CERTIFICATE_VERSION_V3.get(py)?),
        _ => Err(CryptographyError::from(
            exceptions::InvalidVersion::new_err((
                format!("{version} is not a valid X509 version"),
                version,
            )),
        )),
    }
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, backend=None))]
pub(crate) fn load_pem_x509_certificate(
    py: pyo3::Python<'_>,
    data: &[u8],
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<Certificate> {
    let _ = backend;

    // We support both PEM header strings that OpenSSL does
    // https://github.com/openssl/openssl/blob/5e2d22d53ed322a7124e26a4fbd116a8210eb77a/include/openssl/pem.h#L32-L33
    let parsed = x509::find_in_pem(
        data,
        |p| p.tag() == "CERTIFICATE" || p.tag() == "X509 CERTIFICATE",
        "Valid PEM but no BEGIN CERTIFICATE/END CERTIFICATE delimiters. Are you sure this is a certificate?",
    )?;
    load_der_x509_certificate(
        py,
        pyo3::types::PyBytes::new(py, parsed.contents()).unbind(),
        None,
    )
}

#[pyo3::pyfunction]
pub(crate) fn load_pem_x509_certificates(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> CryptographyResult<Vec<Certificate>> {
    let certs = pem::parse_many(data)?
        .iter()
        .filter(|p| p.tag() == "CERTIFICATE" || p.tag() == "X509 CERTIFICATE")
        .map(|p| {
            load_der_x509_certificate(
                py,
                pyo3::types::PyBytes::new(py, p.contents()).unbind(),
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err(CryptographyError::from(pem::PemError::MalformedFraming));
    }

    Ok(certs)
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, backend=None))]
pub(crate) fn load_der_x509_certificate(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<Certificate> {
    let _ = backend;

    let raw = OwnedCertificate::try_new(data, |data| asn1::parse_single(data.as_bytes(py)))?;
    // Parse cert version immediately so we can raise error on parse if it is invalid.
    cert_version(py, raw.borrow_dependent().tbs_cert.version)?;
    // determine if the serial is negative and raise a warning if it is. We want to drop support
    // for this sort of invalid encoding eventually.
    warn_if_negative_serial(py, raw.borrow_dependent().tbs_cert.serial.as_bytes())?;
    // determine if the signature algorithm has incorrect parameters and raise a warning if it
    // does. this is a bug in the JDK and we want to drop support for it eventually.
    // ECDSA was fixed in Java 16, DSA in Java 21.
    warn_if_invalid_params(py, raw.borrow_dependent().signature_alg.params.clone())?;
    warn_if_invalid_params(
        py,
        raw.borrow_dependent().tbs_cert.signature_alg.params.clone(),
    )?;

    Ok(Certificate {
        raw,
        cached_extensions: pyo3::sync::GILOnceCell::new(),
    })
}

fn warn_if_negative_serial(py: pyo3::Python<'_>, bytes: &'_ [u8]) -> pyo3::PyResult<()> {
    if bytes[0] & 0x80 != 0 {
        let warning_cls = types::DEPRECATED_IN_36.get(py)?;
        let message = cstr_from_literal!("Parsed a negative serial number, which is disallowed by RFC 5280. Loading this certificate will cause an exception in the next release of cryptography.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
    }
    Ok(())
}

fn warn_if_invalid_params(
    py: pyo3::Python<'_>,
    params: AlgorithmParameters<'_>,
) -> pyo3::PyResult<()> {
    match params {
        AlgorithmParameters::EcDsaWithSha224(Some(..))
        | AlgorithmParameters::EcDsaWithSha256(Some(..))
        | AlgorithmParameters::EcDsaWithSha384(Some(..))
        | AlgorithmParameters::EcDsaWithSha512(Some(..))
        | AlgorithmParameters::DsaWithSha224(Some(..))
        | AlgorithmParameters::DsaWithSha256(Some(..))
        | AlgorithmParameters::DsaWithSha384(Some(..))
        | AlgorithmParameters::DsaWithSha512(Some(..)) => {
            // This can also be triggered by an Intel On Die certificate
            // https://github.com/pyca/cryptography/issues/11723
            let warning_cls = types::DEPRECATED_IN_41.get(py)?;
            let message = cstr_from_literal!("The parsed certificate contains a NULL parameter value in its signature algorithm parameters. This is invalid and will be rejected in a future version of cryptography. If this certificate was created via Java, please upgrade to JDK21+ or the latest JDK11/17 once a fix is issued. If this certificate was created in some other fashion please report the issue to the cryptography issue tracker. See https://github.com/pyca/cryptography/issues/8996 and https://github.com/pyca/cryptography/issues/9253 for more details.");
            pyo3::PyErr::warn(py, &warning_cls, message, 2)?;
        }
        _ => {}
    }
    Ok(())
}

fn parse_display_text<'p>(
    py: pyo3::Python<'p>,
    text: DisplayText<'_>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    match text {
        DisplayText::IA5String(o) => Ok(pyo3::types::PyString::new(py, o.as_str()).into_any()),
        DisplayText::Utf8String(o) => Ok(pyo3::types::PyString::new(py, o.as_str()).into_any()),
        DisplayText::VisibleString(o) => {
            if asn1::VisibleString::new(o.as_str()).is_none() {
                let warning_cls = types::DEPRECATED_IN_41.get(py)?;
                let message = cstr_from_literal!("Invalid ASN.1 (UTF-8 characters in a VisibleString) in the explicit text and/or notice reference of the certificate policies extension. In a future version of cryptography, an exception will be raised.");
                pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
            }
            Ok(pyo3::types::PyString::new(py, o.as_str()).into_any())
        }
        DisplayText::BmpString(o) => {
            let py_bytes = pyo3::types::PyBytes::new(py, o.as_utf16_be_bytes());
            // TODO: do the string conversion in rust perhaps
            Ok(py_bytes.call_method1(
                pyo3::intern!(py, "decode"),
                (pyo3::intern!(py, "utf_16_be"),),
            )?)
        }
    }
}

fn parse_user_notice<'p>(
    py: pyo3::Python<'p>,
    un: UserNotice<'_, Asn1Read>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let et = match un.explicit_text {
        Some(data) => parse_display_text(py, data)?,
        None => py.None().into_bound(py),
    };
    let nr = match un.notice_ref {
        Some(data) => {
            let org = parse_display_text(py, data.organization)?;
            let numbers = pyo3::types::PyList::empty(py);
            for num in data.notice_numbers.clone() {
                numbers.append(big_byte_slice_to_py_int(py, num.as_bytes())?)?;
            }
            types::NOTICE_REFERENCE.get(py)?.call1((org, numbers))?
        }
        None => py.None().into_bound(py),
    };
    Ok(types::USER_NOTICE.get(py)?.call1((nr, et))?)
}

fn parse_policy_qualifiers<'a>(
    py: pyo3::Python<'a>,
    policy_qualifiers: &asn1::SequenceOf<'a, PolicyQualifierInfo<'a, Asn1Read>>,
) -> CryptographyResult<pyo3::Bound<'a, pyo3::PyAny>> {
    let py_pq = pyo3::types::PyList::empty(py);
    for pqi in policy_qualifiers.clone() {
        let qualifier = match pqi.qualifier {
            Qualifier::CpsUri(data) => {
                if pqi.policy_qualifier_id == oid::CP_CPS_URI_OID {
                    pyo3::types::PyString::new(py, data.as_str()).into_any()
                } else {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "CpsUri ASN.1 structure found but OID did not match",
                        ),
                    ));
                }
            }
            Qualifier::UserNotice(un) => {
                if pqi.policy_qualifier_id != oid::CP_USER_NOTICE_OID {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "UserNotice ASN.1 structure found but OID did not match",
                        ),
                    ));
                }
                parse_user_notice(py, un)?
            }
        };
        py_pq.append(qualifier)?;
    }
    Ok(py_pq.into_any())
}

fn parse_cp<'p>(
    py: pyo3::Python<'p>,
    ext: &Extension<'_>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let cp = ext.value::<asn1::SequenceOf<'_, PolicyInformation<'_, Asn1Read>>>()?;
    let certificate_policies = pyo3::types::PyList::empty(py);
    for policyinfo in cp {
        let pi_oid = oid_to_py_oid(py, &policyinfo.policy_identifier)?;
        let py_pqis = match policyinfo.policy_qualifiers {
            Some(policy_qualifiers) => parse_policy_qualifiers(py, &policy_qualifiers)?,
            None => py.None().into_bound(py),
        };
        let pi = types::POLICY_INFORMATION
            .get(py)?
            .call1((pi_oid, py_pqis))?;
        certificate_policies.append(pi)?;
    }
    Ok(certificate_policies.into_any())
}

fn parse_general_subtrees<'p>(
    py: pyo3::Python<'p>,
    subtrees: SequenceOfSubtrees<'_, Asn1Read>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let gns = pyo3::types::PyList::empty(py);
    for gs in subtrees {
        gns.append(x509::parse_general_name(py, gs.base)?)?;
    }
    Ok(gns.into_any())
}

pub(crate) fn parse_distribution_point_name<'p>(
    py: pyo3::Python<'p>,
    dp: DistributionPointName<'p, Asn1Read>,
) -> CryptographyResult<(pyo3::Bound<'p, pyo3::PyAny>, pyo3::Bound<'p, pyo3::PyAny>)> {
    Ok(match dp {
        DistributionPointName::FullName(data) => (
            x509::parse_general_names(py, &data)?,
            py.None().into_bound(py),
        ),
        DistributionPointName::NameRelativeToCRLIssuer(data) => {
            (py.None().into_bound(py), x509::parse_rdn(py, &data)?)
        }
    })
}

fn parse_distribution_point<'p>(
    py: pyo3::Python<'p>,
    dp: DistributionPoint<'p, Asn1Read>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let (full_name, relative_name) = match dp.distribution_point {
        Some(data) => parse_distribution_point_name(py, data)?,
        None => (py.None().into_bound(py), py.None().into_bound(py)),
    };
    let reasons = parse_distribution_point_reasons(py, dp.reasons.as_ref())?;
    let crl_issuer = match dp.crl_issuer {
        Some(aci) => x509::parse_general_names(py, &aci)?,
        None => py.None().into_bound(py),
    };
    Ok(types::DISTRIBUTION_POINT
        .get(py)?
        .call1((full_name, relative_name, reasons, crl_issuer))?)
}

pub(crate) fn parse_distribution_points<'p>(
    py: pyo3::Python<'p>,
    ext: &Extension<'_>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let dps = ext.value::<asn1::SequenceOf<'_, DistributionPoint<'_, Asn1Read>>>()?;
    let py_dps = pyo3::types::PyList::empty(py);
    for dp in dps {
        let py_dp = parse_distribution_point(py, dp)?;
        py_dps.append(py_dp)?;
    }
    Ok(py_dps.into_any())
}

pub(crate) fn parse_distribution_point_reasons<'p>(
    py: pyo3::Python<'p>,
    reasons: Option<&asn1::BitString<'_>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let reason_bit_mapping = types::REASON_BIT_MAPPING.get(py)?;

    Ok(match reasons {
        Some(bs) => {
            let mut vec = Vec::new();
            for i in 1..=8 {
                if bs.has_bit_set(i) {
                    vec.push(reason_bit_mapping.get_item(i)?);
                }
            }
            pyo3::types::PyFrozenSet::new(py, &vec)?.into_any()
        }
        None => py.None().into_bound(py),
    })
}

pub(crate) fn encode_distribution_point_reasons(
    py: pyo3::Python<'_>,
    py_reasons: &pyo3::Bound<'_, pyo3::PyAny>,
) -> pyo3::PyResult<asn1::OwnedBitString> {
    let reason_flag_mapping = types::CRL_REASON_FLAGS.get(py)?;

    let mut bits = vec![0, 0];
    for py_reason in py_reasons.try_iter()? {
        let bit = reason_flag_mapping
            .get_item(py_reason?)?
            .extract::<usize>()?;
        set_bit(&mut bits, bit, true);
    }
    if bits[1] == 0 {
        bits.truncate(1);
    }
    let unused_bits = bits.last().unwrap().trailing_zeros() as u8;
    Ok(asn1::OwnedBitString::new(bits, unused_bits).unwrap())
}

pub(crate) fn parse_authority_key_identifier<'p>(
    py: pyo3::Python<'p>,
    ext: &Extension<'p>,
) -> Result<pyo3::Bound<'p, pyo3::PyAny>, CryptographyError> {
    let aki = ext.value::<AuthorityKeyIdentifier<'_, Asn1Read>>()?;
    let serial = match aki.authority_cert_serial_number {
        Some(biguint) => big_byte_slice_to_py_int(py, biguint.as_bytes())?.unbind(),
        None => py.None(),
    };
    let issuer = match aki.authority_cert_issuer {
        Some(aci) => x509::parse_general_names(py, &aci)?,
        None => py.None().into_bound(py),
    };
    Ok(types::AUTHORITY_KEY_IDENTIFIER
        .get(py)?
        .call1((aki.key_identifier, issuer, serial))?)
}

pub(crate) fn parse_access_descriptions<'p>(
    py: pyo3::Python<'p>,
    ext: &Extension<'_>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let ads = pyo3::types::PyList::empty(py);
    let parsed = ext.value::<SequenceOfAccessDescriptions<'_, Asn1Read>>()?;
    for access in parsed {
        let py_oid = oid_to_py_oid(py, &access.access_method)?;
        let gn = x509::parse_general_name(py, access.access_location)?;
        let ad = types::ACCESS_DESCRIPTION.get(py)?.call1((py_oid, gn))?;
        ads.append(ad)?;
    }
    Ok(ads.into_any())
}

fn parse_naming_authority<'p>(
    py: pyo3::Python<'p>,
    authority: NamingAuthority<'_>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let py_id = match &authority.id {
        Some(data) => oid_to_py_oid(py, data)?,
        None => py.None().into_bound(py),
    };
    let py_url = match authority.url {
        Some(data) => pyo3::types::PyString::new(py, data.as_str()).into_any(),
        None => py.None().into_bound(py),
    };
    let py_text = match authority.text {
        Some(data) => parse_display_text(py, data)?,
        None => py.None().into_bound(py),
    };

    Ok(types::NAMING_AUTHORITY
        .get(py)?
        .call1((py_id, py_url, py_text))?)
}

fn parse_profession_infos<'p, 'a>(
    py: pyo3::Python<'p>,
    profession_infos: &asn1::SequenceOf<'a, ProfessionInfo<'a, Asn1Read>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let py_infos = pyo3::types::PyList::empty(py);
    for info in profession_infos.clone() {
        let py_naming_authority = match info.naming_authority {
            Some(data) => parse_naming_authority(py, data)?,
            None => py.None().into_bound(py),
        };
        let py_profession_items = pyo3::types::PyList::empty(py);
        for item in info.profession_items {
            let py_item = parse_display_text(py, item)?;
            py_profession_items.append(py_item)?;
        }
        let py_profession_oids = match info.profession_oids {
            Some(oids) => {
                let py_oids = pyo3::types::PyList::empty(py);
                for oid in oids {
                    let py_oid = oid_to_py_oid(py, &oid)?;
                    py_oids.append(py_oid)?;
                }
                py_oids.into_any()
            }
            None => py.None().into_bound(py),
        };
        let py_registration_number = match info.registration_number {
            Some(data) => pyo3::types::PyString::new(py, data.as_str()).into_any(),
            None => py.None().into_bound(py),
        };
        let py_add_profession_info = match info.add_profession_info {
            Some(data) => pyo3::types::PyBytes::new(py, data).into_any(),
            None => py.None().into_bound(py),
        };
        let py_info = types::PROFESSION_INFO.get(py)?.call1((
            py_naming_authority,
            py_profession_items,
            py_profession_oids,
            py_registration_number,
            py_add_profession_info,
        ))?;
        py_infos.append(py_info)?;
    }
    Ok(py_infos.into_any())
}

fn parse_admissions<'p, 'a>(
    py: pyo3::Python<'p>,
    admissions: &asn1::SequenceOf<'a, Admission<'a, Asn1Read>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let py_admissions = pyo3::types::PyList::empty(py);
    for admission in admissions.clone() {
        let py_admission_authority = match admission.admission_authority {
            Some(authority) => x509::parse_general_name(py, authority)?,
            None => py.None().into_bound(py),
        };
        let py_naming_authority = match admission.naming_authority {
            Some(data) => parse_naming_authority(py, data)?,
            None => py.None().into_bound(py),
        };
        let py_infos = parse_profession_infos(py, &admission.profession_infos)?;

        let py_entry = types::ADMISSION.get(py)?.call1((
            py_admission_authority,
            py_naming_authority,
            py_infos,
        ))?;
        py_admissions.append(py_entry)?;
    }
    Ok(py_admissions.into_any())
}

pub fn parse_cert_ext<'p>(
    py: pyo3::Python<'p>,
    ext: &Extension<'p>,
) -> CryptographyResult<Option<pyo3::Bound<'p, pyo3::PyAny>>> {
    match ext.extn_id {
        oid::SUBJECT_ALTERNATIVE_NAME_OID => {
            let gn_seq = ext.value::<SubjectAlternativeName<'_>>().map_err(|e| {
                e.add_location(asn1::ParseLocation::Field("subject_alternative_name"))
            })?;
            let sans = x509::parse_general_names(py, &gn_seq)?;
            Ok(Some(
                types::SUBJECT_ALTERNATIVE_NAME.get(py)?.call1((sans,))?,
            ))
        }
        oid::ISSUER_ALTERNATIVE_NAME_OID => {
            let gn_seq = ext.value::<IssuerAlternativeName<'_>>().map_err(|e| {
                e.add_location(asn1::ParseLocation::Field("issuer_alternative_name"))
            })?;
            let ians = x509::parse_general_names(py, &gn_seq)?;
            Ok(Some(
                types::ISSUER_ALTERNATIVE_NAME.get(py)?.call1((ians,))?,
            ))
        }
        oid::TLS_FEATURE_OID => {
            let tls_feature_type_to_enum = types::TLS_FEATURE_TYPE_TO_ENUM.get(py)?;

            let features = pyo3::types::PyList::empty(py);
            for feature in ext.value::<asn1::SequenceOf<'_, u64>>()? {
                let py_feature = tls_feature_type_to_enum.get_item(feature)?;
                features.append(py_feature)?;
            }
            Ok(Some(types::TLS_FEATURE.get(py)?.call1((features,))?))
        }
        oid::SUBJECT_KEY_IDENTIFIER_OID => {
            let identifier = ext.value::<&[u8]>()?;
            Ok(Some(
                types::SUBJECT_KEY_IDENTIFIER
                    .get(py)?
                    .call1((identifier,))?,
            ))
        }
        oid::EXTENDED_KEY_USAGE_OID => {
            let ekus = pyo3::types::PyList::empty(py);
            for oid in ext.value::<ExtendedKeyUsage<'_>>()? {
                let oid_obj = oid_to_py_oid(py, &oid)?;
                ekus.append(oid_obj)?;
            }
            Ok(Some(types::EXTENDED_KEY_USAGE.get(py)?.call1((ekus,))?))
        }
        oid::KEY_USAGE_OID => {
            let kus = ext.value::<KeyUsage<'_>>()?;

            Ok(Some(types::KEY_USAGE.get(py)?.call1((
                kus.digital_signature(),
                kus.content_commitment(),
                kus.key_encipherment(),
                kus.data_encipherment(),
                kus.key_agreement(),
                kus.key_cert_sign(),
                kus.crl_sign(),
                kus.encipher_only(),
                kus.decipher_only(),
            ))?))
        }
        oid::AUTHORITY_INFORMATION_ACCESS_OID => {
            let ads = parse_access_descriptions(py, ext)?;
            Ok(Some(
                types::AUTHORITY_INFORMATION_ACCESS.get(py)?.call1((ads,))?,
            ))
        }
        oid::SUBJECT_INFORMATION_ACCESS_OID => {
            let ads = parse_access_descriptions(py, ext)?;
            Ok(Some(
                types::SUBJECT_INFORMATION_ACCESS.get(py)?.call1((ads,))?,
            ))
        }
        oid::CERTIFICATE_POLICIES_OID => {
            let cp = parse_cp(py, ext)?;
            Ok(Some(types::CERTIFICATE_POLICIES.get(py)?.call1((cp,))?))
        }
        oid::POLICY_CONSTRAINTS_OID => {
            let pc = ext.value::<PolicyConstraints>()?;
            Ok(Some(types::POLICY_CONSTRAINTS.get(py)?.call1((
                pc.require_explicit_policy,
                pc.inhibit_policy_mapping,
            ))?))
        }
        oid::OCSP_NO_CHECK_OID => {
            ext.value::<()>()?;
            Ok(Some(types::OCSP_NO_CHECK.get(py)?.call0()?))
        }
        oid::INHIBIT_ANY_POLICY_OID => {
            let bignum = ext.value::<asn1::BigUint<'_>>()?;
            let pynum = big_byte_slice_to_py_int(py, bignum.as_bytes())?;
            Ok(Some(types::INHIBIT_ANY_POLICY.get(py)?.call1((pynum,))?))
        }
        oid::BASIC_CONSTRAINTS_OID => {
            let bc = ext.value::<BasicConstraints>()?;
            Ok(Some(
                types::BASIC_CONSTRAINTS
                    .get(py)?
                    .call1((bc.ca, bc.path_length))?,
            ))
        }
        oid::AUTHORITY_KEY_IDENTIFIER_OID => Ok(Some(parse_authority_key_identifier(py, ext)?)),
        oid::CRL_DISTRIBUTION_POINTS_OID => {
            let dp = parse_distribution_points(py, ext)?;
            Ok(Some(types::CRL_DISTRIBUTION_POINTS.get(py)?.call1((dp,))?))
        }
        oid::FRESHEST_CRL_OID => {
            let dp = parse_distribution_points(py, ext)?;
            Ok(Some(types::FRESHEST_CRL.get(py)?.call1((dp,))?))
        }
        oid::NAME_CONSTRAINTS_OID => {
            let nc = ext.value::<NameConstraints<'_, Asn1Read>>()?;
            let permitted_subtrees = match nc.permitted_subtrees {
                Some(data) => parse_general_subtrees(py, data)?,
                None => py.None().into_bound(py),
            };
            let excluded_subtrees = match nc.excluded_subtrees {
                Some(data) => parse_general_subtrees(py, data)?,
                None => py.None().into_bound(py),
            };
            Ok(Some(
                types::NAME_CONSTRAINTS
                    .get(py)?
                    .call1((permitted_subtrees, excluded_subtrees))?,
            ))
        }
        oid::MS_CERTIFICATE_TEMPLATE => {
            let ms_cert_tpl = ext.value::<MSCertificateTemplate>()?;
            let py_oid = oid_to_py_oid(py, &ms_cert_tpl.template_id)?;
            Ok(Some(types::MS_CERTIFICATE_TEMPLATE.get(py)?.call1((
                py_oid,
                ms_cert_tpl.major_version,
                ms_cert_tpl.minor_version,
            ))?))
        }
        oid::ADMISSIONS_OID => {
            let admissions = ext.value::<Admissions<'_, Asn1Read>>()?;
            let admission_authority = match admissions.admission_authority {
                Some(authority) => x509::parse_general_name(py, authority)?,
                None => py.None().into_bound(py),
            };
            let py_admissions = parse_admissions(py, &admissions.contents_of_admissions)?;
            Ok(Some(
                types::ADMISSIONS
                    .get(py)?
                    .call1((admission_authority, py_admissions))?,
            ))
        }
        _ => Ok(None),
    }
}

pub(crate) fn time_from_py(
    py: pyo3::Python<'_>,
    val: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<common::Time> {
    let dt = x509::py_to_datetime(py, val.clone())?;
    time_from_datetime(dt)
}

pub(crate) fn time_from_datetime(dt: asn1::DateTime) -> CryptographyResult<common::Time> {
    if dt.year() >= 2050 {
        Ok(common::Time::GeneralizedTime(
            asn1::X509GeneralizedTime::new(dt)?,
        ))
    } else {
        Ok(common::Time::UtcTime(asn1::UtcTime::new(dt).unwrap()))
    }
}

#[pyo3::pyfunction]
pub(crate) fn create_x509_certificate(
    py: pyo3::Python<'_>,
    builder: &pyo3::Bound<'_, pyo3::PyAny>,
    private_key: &pyo3::Bound<'_, pyo3::PyAny>,
    hash_algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    rsa_padding: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Certificate> {
    let sigalg = x509::sign::compute_signature_algorithm(
        py,
        private_key.clone(),
        hash_algorithm.clone(),
        rsa_padding.clone(),
    )?;

    let der = types::ENCODING_DER.get(py)?;
    let spki = types::PUBLIC_FORMAT_SUBJECT_PUBLIC_KEY_INFO.get(py)?;
    let spki_bytes = builder
        .getattr(pyo3::intern!(py, "_public_key"))?
        .call_method1(pyo3::intern!(py, "public_bytes"), (der, spki))?
        .extract::<pyo3::pybacked::PyBackedBytes>()?;

    let py_serial = builder
        .getattr(pyo3::intern!(py, "_serial_number"))?
        .extract()?;

    let py_issuer_name = builder.getattr(pyo3::intern!(py, "_issuer_name"))?;
    let py_subject_name = builder.getattr(pyo3::intern!(py, "_subject_name"))?;
    let py_not_before = builder.getattr(pyo3::intern!(py, "_not_valid_before"))?;
    let py_not_after = builder.getattr(pyo3::intern!(py, "_not_valid_after"))?;

    let ka_vec = cryptography_keepalive::KeepAlive::new();
    let ka_bytes = cryptography_keepalive::KeepAlive::new();

    let serial_bytes = py_uint_to_big_endian_bytes(py, py_serial)?;

    let ka = cryptography_keepalive::KeepAlive::new();

    let tbs_cert = cryptography_x509::certificate::TbsCertificate {
        version: builder
            .getattr(pyo3::intern!(py, "_version"))?
            .getattr(pyo3::intern!(py, "value"))?
            .extract()?,
        serial: asn1::BigInt::new(&serial_bytes).unwrap(),
        signature_alg: sigalg.clone(),
        issuer: x509::common::encode_name(py, &ka, &py_issuer_name)?,
        validity: cryptography_x509::certificate::Validity {
            not_before: time_from_py(py, &py_not_before)?,
            not_after: time_from_py(py, &py_not_after)?,
        },
        subject: x509::common::encode_name(py, &ka, &py_subject_name)?,
        spki: asn1::parse_single(&spki_bytes)?,
        issuer_unique_id: None,
        subject_unique_id: None,
        raw_extensions: x509::common::encode_extensions(
            py,
            &ka_vec,
            &ka_bytes,
            &builder.getattr(pyo3::intern!(py, "_extensions"))?,
            extensions::encode_extension,
        )?,
    };

    let tbs_bytes = asn1::write_single(&tbs_cert)?;
    let signature = x509::sign::sign_data(
        py,
        private_key.clone(),
        hash_algorithm.clone(),
        rsa_padding.clone(),
        &tbs_bytes,
    )?;
    let data = asn1::write_single(&cryptography_x509::certificate::Certificate {
        tbs_cert,
        signature_alg: sigalg,
        signature: asn1::BitString::new(&signature, 0).unwrap(),
    })?;
    load_der_x509_certificate(py, pyo3::types::PyBytes::new(py, &data).unbind(), None)
}

pub(crate) fn set_bit(vals: &mut [u8], n: usize, set: bool) {
    let idx = n / 8;
    let v = 1 << (7 - (n & 0x07));
    if set {
        vals[idx] |= v;
    }
}
