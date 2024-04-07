// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common::Asn1Write;
use cryptography_x509::{crl, extensions, oid};
use pyo3::pybacked::PyBackedStr;
use pyo3::types::PyAnyMethods;

use crate::asn1::{py_oid_to_oid, py_uint_to_big_endian_bytes};
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509::{certificate, sct};
use crate::{types, x509};

fn encode_general_subtrees<'a>(
    py: pyo3::Python<'_>,
    ka_bytes: &'a cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedBytes>,
    ka_str: &'a cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedStr>,
    subtrees: &pyo3::Bound<'a, pyo3::PyAny>,
) -> Result<Option<extensions::SequenceOfSubtrees<'a, Asn1Write>>, CryptographyError> {
    if subtrees.is_none() {
        Ok(None)
    } else {
        let mut subtree_seq = vec![];
        for name in subtrees.try_iter()? {
            let gn = x509::common::encode_general_name(py, ka_bytes, ka_str, &name?)?;
            subtree_seq.push(extensions::GeneralSubtree {
                base: gn,
                minimum: 0,
                maximum: None,
            });
        }
        Ok(Some(asn1::SequenceOfWriter::new(subtree_seq)))
    }
}

pub(crate) fn encode_authority_key_identifier<'a>(
    py: pyo3::Python<'a>,
    py_aki: &pyo3::Bound<'a, pyo3::PyAny>,
) -> CryptographyResult<Vec<u8>> {
    #[derive(pyo3::FromPyObject)]
    struct PyAuthorityKeyIdentifier<'a> {
        key_identifier: Option<pyo3::pybacked::PyBackedBytes>,
        authority_cert_issuer: Option<pyo3::Bound<'a, pyo3::PyAny>>,
        authority_cert_serial_number: Option<pyo3::Bound<'a, pyo3::types::PyInt>>,
    }
    let aki = py_aki.extract::<PyAuthorityKeyIdentifier<'_>>()?;

    let ka_bytes = cryptography_keepalive::KeepAlive::new();
    let ka_str = cryptography_keepalive::KeepAlive::new();
    let authority_cert_issuer = if let Some(authority_cert_issuer) = aki.authority_cert_issuer {
        let gns =
            x509::common::encode_general_names(py, &ka_bytes, &ka_str, &authority_cert_issuer)?;
        Some(asn1::SequenceOfWriter::new(gns))
    } else {
        None
    };
    let serial_bytes;
    let authority_cert_serial_number =
        if let Some(authority_cert_serial_number) = aki.authority_cert_serial_number {
            serial_bytes = py_uint_to_big_endian_bytes(py, authority_cert_serial_number)?;
            Some(asn1::BigUint::new(&serial_bytes).unwrap())
        } else {
            None
        };
    Ok(asn1::write_single(&extensions::AuthorityKeyIdentifier::<
        Asn1Write,
    > {
        authority_cert_issuer,
        authority_cert_serial_number,
        key_identifier: aki.key_identifier.as_deref(),
    })?)
}

pub(crate) fn encode_distribution_points<'p>(
    py: pyo3::Python<'p>,
    py_dps: &pyo3::Bound<'p, pyo3::PyAny>,
) -> CryptographyResult<Vec<u8>> {
    #[derive(pyo3::FromPyObject)]
    struct PyDistributionPoint<'a> {
        crl_issuer: Option<pyo3::Bound<'a, pyo3::PyAny>>,
        full_name: Option<pyo3::Bound<'a, pyo3::PyAny>>,
        relative_name: Option<pyo3::Bound<'a, pyo3::PyAny>>,
        reasons: Option<pyo3::Bound<'a, pyo3::PyAny>>,
    }

    let ka_bytes = cryptography_keepalive::KeepAlive::new();
    let ka_str = cryptography_keepalive::KeepAlive::new();
    let mut dps = vec![];
    for py_dp in py_dps.try_iter()? {
        let py_dp = py_dp?.extract::<PyDistributionPoint<'_>>()?;

        let crl_issuer = if let Some(py_crl_issuer) = py_dp.crl_issuer {
            let gns = x509::common::encode_general_names(py, &ka_bytes, &ka_str, &py_crl_issuer)?;
            Some(asn1::SequenceOfWriter::new(gns))
        } else {
            None
        };
        let distribution_point = if let Some(py_full_name) = py_dp.full_name {
            let gns = x509::common::encode_general_names(py, &ka_bytes, &ka_str, &py_full_name)?;
            Some(extensions::DistributionPointName::FullName(
                asn1::SequenceOfWriter::new(gns),
            ))
        } else if let Some(py_relative_name) = py_dp.relative_name {
            let mut name_entries = vec![];
            for py_name_entry in py_relative_name.try_iter()? {
                let ne = x509::common::encode_name_entry(py, &ka_bytes, &py_name_entry?)?;
                name_entries.push(ne);
            }
            Some(extensions::DistributionPointName::NameRelativeToCRLIssuer(
                asn1::SetOfWriter::new(name_entries),
            ))
        } else {
            None
        };
        let reasons = if let Some(py_reasons) = py_dp.reasons {
            let reasons = certificate::encode_distribution_point_reasons(py, &py_reasons)?;
            Some(reasons)
        } else {
            None
        };
        dps.push(extensions::DistributionPoint::<Asn1Write> {
            crl_issuer,
            distribution_point,
            reasons,
        });
    }
    Ok(asn1::write_single(&asn1::SequenceOfWriter::new(dps))?)
}

fn encode_basic_constraints(ext: &pyo3::Bound<'_, pyo3::PyAny>) -> CryptographyResult<Vec<u8>> {
    #[derive(pyo3::FromPyObject)]
    struct PyBasicConstraints {
        ca: bool,
        path_length: Option<u64>,
    }
    let pybc = ext.extract::<PyBasicConstraints>()?;
    let bc = extensions::BasicConstraints {
        ca: pybc.ca,
        path_length: pybc.path_length,
    };
    Ok(asn1::write_single(&bc)?)
}

fn encode_key_usage(
    py: pyo3::Python<'_>,
    ext: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Vec<u8>> {
    let mut bs = [0, 0];
    certificate::set_bit(
        &mut bs,
        0,
        ext.getattr(pyo3::intern!(py, "digital_signature"))?
            .is_truthy()?,
    );
    certificate::set_bit(
        &mut bs,
        1,
        ext.getattr(pyo3::intern!(py, "content_commitment"))?
            .is_truthy()?,
    );
    certificate::set_bit(
        &mut bs,
        2,
        ext.getattr(pyo3::intern!(py, "key_encipherment"))?
            .is_truthy()?,
    );
    certificate::set_bit(
        &mut bs,
        3,
        ext.getattr(pyo3::intern!(py, "data_encipherment"))?
            .is_truthy()?,
    );
    certificate::set_bit(
        &mut bs,
        4,
        ext.getattr(pyo3::intern!(py, "key_agreement"))?
            .is_truthy()?,
    );
    certificate::set_bit(
        &mut bs,
        5,
        ext.getattr(pyo3::intern!(py, "key_cert_sign"))?
            .is_truthy()?,
    );
    certificate::set_bit(
        &mut bs,
        6,
        ext.getattr(pyo3::intern!(py, "crl_sign"))?.is_truthy()?,
    );
    if ext
        .getattr(pyo3::intern!(py, "key_agreement"))?
        .is_truthy()?
    {
        certificate::set_bit(
            &mut bs,
            7,
            ext.getattr(pyo3::intern!(py, "encipher_only"))?
                .is_truthy()?,
        );
        certificate::set_bit(
            &mut bs,
            8,
            ext.getattr(pyo3::intern!(py, "decipher_only"))?
                .is_truthy()?,
        );
    }
    let (bits, unused_bits) = if bs[1] == 0 {
        if bs[0] == 0 {
            (&[][..], 0)
        } else {
            (&bs[..1], bs[0].trailing_zeros() as u8)
        }
    } else {
        (&bs[..], bs[1].trailing_zeros() as u8)
    };
    let v = asn1::BitString::new(bits, unused_bits).unwrap();
    Ok(asn1::write_single(&v)?)
}

fn encode_certificate_policies(
    py: pyo3::Python<'_>,
    ext: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Vec<u8>> {
    let mut policy_informations = vec![];
    let ka_bytes = cryptography_keepalive::KeepAlive::new();
    let ka_str = cryptography_keepalive::KeepAlive::new();
    for py_policy_info in ext.try_iter()? {
        let py_policy_info = py_policy_info?;
        let py_policy_qualifiers =
            py_policy_info.getattr(pyo3::intern!(py, "policy_qualifiers"))?;
        let qualifiers = if py_policy_qualifiers.is_truthy()? {
            let mut qualifiers = vec![];
            for py_qualifier in py_policy_qualifiers.try_iter()? {
                let py_qualifier = py_qualifier?;
                let qualifier = if py_qualifier.is_instance_of::<pyo3::types::PyString>() {
                    let py_qualifier_str = ka_str.add(py_qualifier.extract::<PyBackedStr>()?);
                    let cps_uri = match asn1::IA5String::new(py_qualifier_str) {
                        Some(s) => s,
                        None => {
                            return Err(pyo3::exceptions::PyValueError::new_err(
                                "Qualifier must be an ASCII-string.",
                            )
                            .into())
                        }
                    };
                    extensions::PolicyQualifierInfo {
                        policy_qualifier_id: (oid::CP_CPS_URI_OID).clone(),
                        qualifier: extensions::Qualifier::CpsUri(cps_uri),
                    }
                } else {
                    let py_notice = py_qualifier.getattr(pyo3::intern!(py, "notice_reference"))?;
                    let notice_ref = if py_notice.is_truthy()? {
                        let mut notice_numbers = vec![];
                        for py_num in py_notice
                            .getattr(pyo3::intern!(py, "notice_numbers"))?
                            .try_iter()?
                        {
                            let bytes = ka_bytes
                                .add(py_uint_to_big_endian_bytes(ext.py(), py_num?.extract()?)?);
                            notice_numbers.push(asn1::BigUint::new(bytes).unwrap());
                        }
                        let py_notice_str = ka_str.add(
                            py_notice
                                .getattr(pyo3::intern!(py, "organization"))?
                                .extract::<PyBackedStr>()?,
                        );
                        Some(extensions::NoticeReference {
                            organization: extensions::DisplayText::Utf8String(
                                asn1::Utf8String::new(py_notice_str),
                            ),
                            notice_numbers: asn1::SequenceOfWriter::new(notice_numbers),
                        })
                    } else {
                        None
                    };
                    let py_explicit_text =
                        py_qualifier.getattr(pyo3::intern!(py, "explicit_text"))?;
                    let explicit_text = if py_explicit_text.is_truthy()? {
                        let py_explicit_text_str =
                            ka_str.add(py_explicit_text.extract::<PyBackedStr>()?);
                        Some(extensions::DisplayText::Utf8String(asn1::Utf8String::new(
                            py_explicit_text_str,
                        )))
                    } else {
                        None
                    };

                    extensions::PolicyQualifierInfo {
                        policy_qualifier_id: (oid::CP_USER_NOTICE_OID).clone(),
                        qualifier: extensions::Qualifier::UserNotice(extensions::UserNotice {
                            notice_ref,
                            explicit_text,
                        }),
                    }
                };
                qualifiers.push(qualifier);
            }
            Some(asn1::SequenceOfWriter::new(qualifiers))
        } else {
            None
        };
        let py_policy_id = py_policy_info.getattr(pyo3::intern!(py, "policy_identifier"))?;
        policy_informations.push(extensions::PolicyInformation::<Asn1Write> {
            policy_identifier: py_oid_to_oid(py_policy_id)?,
            policy_qualifiers: qualifiers,
        });
    }
    Ok(asn1::write_single(&asn1::SequenceOfWriter::new(
        policy_informations,
    ))?)
}

fn encode_issuing_distribution_point(
    py: pyo3::Python<'_>,
    ext: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Vec<u8>> {
    let ka_bytes = cryptography_keepalive::KeepAlive::new();
    let ka_str = cryptography_keepalive::KeepAlive::new();

    let only_some_reasons = if ext
        .getattr(pyo3::intern!(py, "only_some_reasons"))?
        .is_truthy()?
    {
        let py_reasons = ext.getattr(pyo3::intern!(py, "only_some_reasons"))?;
        let reasons = certificate::encode_distribution_point_reasons(ext.py(), &py_reasons)?;
        Some(reasons)
    } else {
        None
    };
    let distribution_point = if ext.getattr(pyo3::intern!(py, "full_name"))?.is_truthy()? {
        let py_full_name = ext.getattr(pyo3::intern!(py, "full_name"))?;
        let gns = x509::common::encode_general_names(ext.py(), &ka_bytes, &ka_str, &py_full_name)?;
        Some(extensions::DistributionPointName::FullName(
            asn1::SequenceOfWriter::new(gns),
        ))
    } else if ext
        .getattr(pyo3::intern!(py, "relative_name"))?
        .is_truthy()?
    {
        let mut name_entries = vec![];
        for py_name_entry in ext
            .getattr(pyo3::intern!(py, "relative_name"))?
            .try_iter()?
        {
            let name_entry = x509::common::encode_name_entry(ext.py(), &ka_bytes, &py_name_entry?)?;
            name_entries.push(name_entry);
        }
        Some(extensions::DistributionPointName::NameRelativeToCRLIssuer(
            asn1::SetOfWriter::new(name_entries),
        ))
    } else {
        None
    };

    let idp = crl::IssuingDistributionPoint::<Asn1Write> {
        distribution_point,
        indirect_crl: ext.getattr(pyo3::intern!(py, "indirect_crl"))?.extract()?,
        only_contains_attribute_certs: ext
            .getattr(pyo3::intern!(py, "only_contains_attribute_certs"))?
            .extract()?,
        only_contains_ca_certs: ext
            .getattr(pyo3::intern!(py, "only_contains_ca_certs"))?
            .extract()?,
        only_contains_user_certs: ext
            .getattr(pyo3::intern!(py, "only_contains_user_certs"))?
            .extract()?,
        only_some_reasons,
    };
    Ok(asn1::write_single(&idp)?)
}

fn encode_oid_sequence(ext: &pyo3::Bound<'_, pyo3::PyAny>) -> CryptographyResult<Vec<u8>> {
    let mut oids = vec![];
    for el in ext.try_iter()? {
        let oid = py_oid_to_oid(el?)?;
        oids.push(oid);
    }
    Ok(asn1::write_single(&asn1::SequenceOfWriter::new(oids))?)
}

fn encode_tls_features(
    py: pyo3::Python<'_>,
    ext: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Vec<u8>> {
    // Ideally we'd skip building up a vec and just write directly into the
    // writer. This isn't possible at the moment because the callback to write
    // an asn1::Sequence can't return an error, and we need to handle errors
    // from Python.
    let mut els = vec![];
    for el in ext.try_iter()? {
        els.push(el?.getattr(pyo3::intern!(py, "value"))?.extract::<u64>()?);
    }

    Ok(asn1::write_single(&asn1::SequenceOfWriter::new(els))?)
}

fn encode_scts(ext: &pyo3::Bound<'_, pyo3::PyAny>) -> CryptographyResult<Vec<u8>> {
    let mut length = 0;
    for sct in ext.try_iter()? {
        let sct = sct?.downcast::<sct::Sct>()?.clone();
        length += sct.get().sct_data.len() + 2;
    }

    let mut result = vec![];
    result.extend_from_slice(&(length as u16).to_be_bytes());
    for sct in ext.try_iter()? {
        let sct = sct?.downcast::<sct::Sct>()?.clone();
        result.extend_from_slice(&(sct.get().sct_data.len() as u16).to_be_bytes());
        result.extend_from_slice(&sct.get().sct_data);
    }
    Ok(asn1::write_single(&result.as_slice())?)
}

fn encode_naming_authority<'a>(
    py: pyo3::Python<'_>,
    ka_str: &'a cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedStr>,
    py_naming_authority: &pyo3::Bound<'a, pyo3::PyAny>,
) -> CryptographyResult<extensions::NamingAuthority<'a>> {
    let py_oid = py_naming_authority.getattr(pyo3::intern!(py, "id"))?;
    let id = if !py_oid.is_none() {
        Some(py_oid_to_oid(py_oid)?)
    } else {
        None
    };
    let py_url = py_naming_authority.getattr(pyo3::intern!(py, "url"))?;
    let url = if !py_url.is_none() {
        let py_url_str = ka_str.add(py_url.extract::<PyBackedStr>()?);
        match asn1::IA5String::new(py_url_str) {
            Some(s) => Some(s),
            None => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err("url value must be a valid IA5String"),
                ))
            }
        }
    } else {
        None
    };
    let py_text = py_naming_authority.getattr(pyo3::intern!(py, "text"))?;
    let text = if !py_text.is_none() {
        let py_text_str = ka_str.add(py_text.extract::<PyBackedStr>()?);
        Some(extensions::DisplayText::Utf8String(asn1::Utf8String::new(
            py_text_str,
        )))
    } else {
        None
    };
    Ok(extensions::NamingAuthority { id, url, text })
}

fn encode_profession_info<'a>(
    py: pyo3::Python<'a>,
    ka_bytes: &'a cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedBytes>,
    ka_str: &'a cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedStr>,
    py_info: &pyo3::Bound<'a, pyo3::PyAny>,
) -> CryptographyResult<extensions::ProfessionInfo<'a, Asn1Write>> {
    let py_naming_authority = py_info.getattr(pyo3::intern!(py, "naming_authority"))?;
    let naming_authority = if !py_naming_authority.is_none() {
        Some(encode_naming_authority(py, ka_str, &py_naming_authority)?)
    } else {
        None
    };
    let mut profession_items = vec![];
    let py_items = py_info.getattr(pyo3::intern!(py, "profession_items"))?;
    for py_item in py_items.try_iter()? {
        let py_item = py_item?;
        let py_item_str = ka_str.add(py_item.extract::<PyBackedStr>()?);
        let item = extensions::DisplayText::Utf8String(asn1::Utf8String::new(py_item_str));
        profession_items.push(item);
    }
    let profession_items = asn1::SequenceOfWriter::new(profession_items);
    let py_oids = py_info.getattr(pyo3::intern!(py, "profession_oids"))?;
    let profession_oids = if !py_oids.is_none() {
        let mut profession_oids = vec![];
        for py_oid in py_oids.try_iter()? {
            let py_oid = py_oid?;
            let oid = py_oid_to_oid(py_oid)?;
            profession_oids.push(oid);
        }
        Some(asn1::SequenceOfWriter::new(profession_oids))
    } else {
        None
    };
    let py_registration_number = py_info.getattr(pyo3::intern!(py, "registration_number"))?;
    let registration_number = if !py_registration_number.is_none() {
        let py_registration_number_str =
            ka_str.add(py_registration_number.extract::<PyBackedStr>()?);
        match asn1::PrintableString::new(py_registration_number_str) {
            Some(s) => Some(s),
            None => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "registration_number value must be a valid PrintableString",
                    ),
                ))
            }
        }
    } else {
        None
    };
    let py_add_profession_info = py_info.getattr(pyo3::intern!(py, "add_profession_info"))?;
    let add_profession_info = if !py_add_profession_info.is_none() {
        Some(ka_bytes.add(py_add_profession_info.extract::<pyo3::pybacked::PyBackedBytes>()?))
    } else {
        None
    };
    Ok(extensions::ProfessionInfo {
        naming_authority,
        profession_items,
        profession_oids,
        registration_number,
        add_profession_info,
    })
}

fn encode_admission<'a>(
    py: pyo3::Python<'a>,
    ka_bytes: &'a cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedBytes>,
    ka_str: &'a cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedStr>,
    py_admission: &pyo3::Bound<'a, pyo3::PyAny>,
) -> CryptographyResult<extensions::Admission<'a, Asn1Write>> {
    let py_admission_authority = py_admission.getattr(pyo3::intern!(py, "admission_authority"))?;
    let admission_authority = if !py_admission_authority.is_none() {
        Some(x509::common::encode_general_name(
            py,
            ka_bytes,
            ka_str,
            &py_admission_authority,
        )?)
    } else {
        None
    };
    let py_naming_authority = py_admission.getattr(pyo3::intern!(py, "naming_authority"))?;
    let naming_authority = if !py_naming_authority.is_none() {
        Some(encode_naming_authority(py, ka_str, &py_naming_authority)?)
    } else {
        None
    };

    let py_profession_infos = py_admission.getattr(pyo3::intern!(py, "profession_infos"))?;
    let mut profession_infos = vec![];
    for py_info in py_profession_infos.try_iter()? {
        profession_infos.push(encode_profession_info(py, ka_bytes, ka_str, &py_info?)?);
    }
    let profession_infos = asn1::SequenceOfWriter::new(profession_infos);
    Ok(extensions::Admission {
        admission_authority,
        naming_authority,
        profession_infos,
    })
}

pub(crate) fn encode_extension(
    py: pyo3::Python<'_>,
    oid: &asn1::ObjectIdentifier,
    ext: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Option<Vec<u8>>> {
    match oid {
        &oid::BASIC_CONSTRAINTS_OID => {
            let der = encode_basic_constraints(ext)?;
            Ok(Some(der))
        }
        &oid::SUBJECT_KEY_IDENTIFIER_OID => {
            let digest = ext
                .getattr(pyo3::intern!(py, "digest"))?
                .extract::<pyo3::pybacked::PyBackedBytes>()?;
            Ok(Some(asn1::write_single(&digest.as_ref())?))
        }
        &oid::KEY_USAGE_OID => {
            let der = encode_key_usage(py, ext)?;
            Ok(Some(der))
        }
        &oid::AUTHORITY_INFORMATION_ACCESS_OID | &oid::SUBJECT_INFORMATION_ACCESS_OID => {
            let der = x509::common::encode_access_descriptions(ext.py(), ext)?;
            Ok(Some(der))
        }
        &oid::EXTENDED_KEY_USAGE_OID | &oid::ACCEPTABLE_RESPONSES_OID => {
            let der = encode_oid_sequence(ext)?;
            Ok(Some(der))
        }
        &oid::CERTIFICATE_POLICIES_OID => {
            let der = encode_certificate_policies(py, ext)?;
            Ok(Some(der))
        }
        &oid::POLICY_CONSTRAINTS_OID => {
            let pc = extensions::PolicyConstraints {
                require_explicit_policy: ext
                    .getattr(pyo3::intern!(py, "require_explicit_policy"))?
                    .extract()?,
                inhibit_policy_mapping: ext
                    .getattr(pyo3::intern!(py, "inhibit_policy_mapping"))?
                    .extract()?,
            };
            Ok(Some(asn1::write_single(&pc)?))
        }
        &oid::NAME_CONSTRAINTS_OID => {
            let ka_bytes = cryptography_keepalive::KeepAlive::new();
            let ka_str = cryptography_keepalive::KeepAlive::new();

            let permitted = ext.getattr(pyo3::intern!(py, "permitted_subtrees"))?;
            let excluded = ext.getattr(pyo3::intern!(py, "excluded_subtrees"))?;
            let nc = extensions::NameConstraints::<Asn1Write> {
                permitted_subtrees: encode_general_subtrees(
                    ext.py(),
                    &ka_bytes,
                    &ka_str,
                    &permitted,
                )?,
                excluded_subtrees: encode_general_subtrees(
                    ext.py(),
                    &ka_bytes,
                    &ka_str,
                    &excluded,
                )?,
            };
            Ok(Some(asn1::write_single(&nc)?))
        }
        &oid::INHIBIT_ANY_POLICY_OID => {
            let intval = ext
                .getattr(pyo3::intern!(py, "skip_certs"))?
                .downcast::<pyo3::types::PyInt>()?
                .clone();
            let bytes = py_uint_to_big_endian_bytes(ext.py(), intval)?;
            Ok(Some(asn1::write_single(
                &asn1::BigUint::new(&bytes).unwrap(),
            )?))
        }
        &oid::ISSUER_ALTERNATIVE_NAME_OID | &oid::SUBJECT_ALTERNATIVE_NAME_OID => {
            let ka_bytes = cryptography_keepalive::KeepAlive::new();
            let ka_str = cryptography_keepalive::KeepAlive::new();
            let gns = x509::common::encode_general_names(ext.py(), &ka_bytes, &ka_str, ext)?;
            Ok(Some(asn1::write_single(&asn1::SequenceOfWriter::new(gns))?))
        }
        &oid::AUTHORITY_KEY_IDENTIFIER_OID => {
            let der = encode_authority_key_identifier(ext.py(), ext)?;
            Ok(Some(der))
        }
        &oid::FRESHEST_CRL_OID | &oid::CRL_DISTRIBUTION_POINTS_OID => {
            let der = encode_distribution_points(ext.py(), ext)?;
            Ok(Some(der))
        }
        &oid::OCSP_NO_CHECK_OID => Ok(Some(asn1::write_single(&())?)),
        &oid::TLS_FEATURE_OID => {
            let der = encode_tls_features(py, ext)?;
            Ok(Some(der))
        }
        &oid::PRECERT_POISON_OID => Ok(Some(asn1::write_single(&())?)),
        &oid::PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID
        | &oid::SIGNED_CERTIFICATE_TIMESTAMPS_OID => {
            let der = encode_scts(ext)?;
            Ok(Some(der))
        }
        &oid::CRL_REASON_OID => {
            let value = types::CRL_ENTRY_REASON_ENUM_TO_CODE
                .get(ext.py())?
                .get_item(ext.getattr(pyo3::intern!(py, "reason"))?)?
                .extract::<u32>()?;
            Ok(Some(asn1::write_single(&asn1::Enumerated::new(value))?))
        }
        &oid::CERTIFICATE_ISSUER_OID => {
            let ka_bytes = cryptography_keepalive::KeepAlive::new();
            let ka_str = cryptography_keepalive::KeepAlive::new();
            let gns = x509::common::encode_general_names(ext.py(), &ka_bytes, &ka_str, ext)?;
            Ok(Some(asn1::write_single(&asn1::SequenceOfWriter::new(gns))?))
        }
        &oid::INVALIDITY_DATE_OID => {
            let py_dt = ext.getattr(pyo3::intern!(py, "invalidity_date_utc"))?;
            let dt = x509::py_to_datetime(py, py_dt)?;
            Ok(Some(asn1::write_single(&asn1::X509GeneralizedTime::new(
                dt,
            )?)?))
        }
        &oid::CRL_NUMBER_OID | &oid::DELTA_CRL_INDICATOR_OID => {
            let intval = ext
                .getattr(pyo3::intern!(py, "crl_number"))?
                .downcast::<pyo3::types::PyInt>()?
                .clone();
            let bytes = py_uint_to_big_endian_bytes(ext.py(), intval)?;
            Ok(Some(asn1::write_single(
                &asn1::BigUint::new(&bytes).unwrap(),
            )?))
        }
        &oid::ISSUING_DISTRIBUTION_POINT_OID => {
            let der = encode_issuing_distribution_point(py, ext)?;
            Ok(Some(der))
        }
        &oid::NONCE_OID => {
            let nonce = ext
                .getattr(pyo3::intern!(py, "nonce"))?
                .extract::<pyo3::pybacked::PyBackedBytes>()?;
            Ok(Some(asn1::write_single(&nonce.as_ref())?))
        }
        &oid::MS_CERTIFICATE_TEMPLATE => {
            let py_template_id = ext.getattr(pyo3::intern!(py, "template_id"))?;
            let mstpl = extensions::MSCertificateTemplate {
                template_id: py_oid_to_oid(py_template_id)?,
                major_version: ext.getattr(pyo3::intern!(py, "major_version"))?.extract()?,
                minor_version: ext.getattr(pyo3::intern!(py, "minor_version"))?.extract()?,
            };
            Ok(Some(asn1::write_single(&mstpl)?))
        }
        &oid::ADMISSIONS_OID => {
            let ka_bytes = cryptography_keepalive::KeepAlive::new();
            let ka_str = cryptography_keepalive::KeepAlive::new();
            let py_admission_authority = ext.getattr(pyo3::intern!(py, "authority"))?;
            let admission_authority = if !py_admission_authority.is_none() {
                Some(x509::common::encode_general_name(
                    py,
                    &ka_bytes,
                    &ka_str,
                    &py_admission_authority,
                )?)
            } else {
                None
            };
            let mut admissions = vec![];
            for py_admission in ext.try_iter()? {
                let admission = encode_admission(py, &ka_bytes, &ka_str, &py_admission?)?;
                admissions.push(admission);
            }

            let contents_of_admissions = asn1::SequenceOfWriter::new(admissions);

            let admission = extensions::Admissions::<Asn1Write> {
                admission_authority,
                contents_of_admissions,
            };
            Ok(Some(asn1::write_single(&admission)?))
        }
        _ => Ok(None),
    }
}
