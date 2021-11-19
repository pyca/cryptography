// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{py_uint_to_big_endian_bytes, PyAsn1Error};
use crate::x509;
use crate::x509::{certificate, crl, oid, sct};

fn encode_general_subtrees<'a>(
    py: pyo3::Python<'a>,
    subtrees: &'a pyo3::PyAny,
) -> Result<Option<certificate::SequenceOfSubtrees<'a>>, PyAsn1Error> {
    if subtrees.is_none() {
        Ok(None)
    } else {
        let mut subtree_seq = vec![];
        for name in subtrees.iter()? {
            let gn = x509::common::encode_general_name(py, name?)?;
            subtree_seq.push(certificate::GeneralSubtree {
                base: gn,
                minimum: 0,
                maximum: None,
            });
        }
        Ok(Some(x509::Asn1ReadableOrWritable::new_write(
            asn1::SequenceOfWriter::new(subtree_seq),
        )))
    }
}

pub(crate) fn encode_authority_key_identifier<'a>(
    py: pyo3::Python<'a>,
    py_aki: &'a pyo3::PyAny,
) -> pyo3::PyResult<certificate::AuthorityKeyIdentifier<'a>> {
    let key_identifier = if py_aki.getattr("key_identifier")?.is_none() {
        None
    } else {
        Some(py_aki.getattr("key_identifier")?.extract::<&[u8]>()?)
    };
    let authority_cert_issuer = if py_aki.getattr("authority_cert_issuer")?.is_none() {
        None
    } else {
        let gns = x509::common::encode_general_names(py, py_aki.getattr("authority_cert_issuer")?)?;
        Some(x509::Asn1ReadableOrWritable::new_write(
            asn1::SequenceOfWriter::new(gns),
        ))
    };
    let authority_cert_serial_number = if py_aki.getattr("authority_cert_serial_number")?.is_none()
    {
        None
    } else {
        let py_num = py_aki.getattr("authority_cert_serial_number")?.downcast()?;
        let serial_bytes = py_uint_to_big_endian_bytes(py, py_num)?;
        Some(asn1::BigUint::new(serial_bytes).unwrap())
    };
    Ok(certificate::AuthorityKeyIdentifier {
        key_identifier,
        authority_cert_issuer,
        authority_cert_serial_number,
    })
}

pub(crate) fn encode_distribution_points<'p>(
    py: pyo3::Python<'p>,
    py_dps: &'p pyo3::PyAny,
) -> pyo3::PyResult<Vec<certificate::DistributionPoint<'p>>> {
    let mut dps = vec![];
    for py_dp in py_dps.iter()? {
        let py_dp = py_dp?;

        let crl_issuer = if py_dp.getattr("crl_issuer")?.is_true()? {
            let gns = x509::common::encode_general_names(py, py_dp.getattr("crl_issuer")?)?;
            Some(x509::Asn1ReadableOrWritable::new_write(
                asn1::SequenceOfWriter::new(gns),
            ))
        } else {
            None
        };
        let distribution_point = if py_dp.getattr("full_name")?.is_true()? {
            let gns = x509::common::encode_general_names(py, py_dp.getattr("full_name")?)?;
            Some(certificate::DistributionPointName::FullName(
                x509::Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(gns)),
            ))
        } else if py_dp.getattr("relative_name")?.is_true()? {
            let mut name_entries = vec![];
            for py_name_entry in py_dp.getattr("relative_name")?.iter()? {
                name_entries.push(x509::common::encode_name_entry(py, py_name_entry?)?);
            }
            Some(certificate::DistributionPointName::NameRelativeToCRLIssuer(
                x509::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(name_entries)),
            ))
        } else {
            None
        };
        let reasons = if py_dp.getattr("reasons")?.is_true()? {
            let py_reasons = py_dp.getattr("reasons")?;
            let reasons = certificate::encode_distribution_point_reasons(py, py_reasons)?;
            Some(x509::Asn1ReadableOrWritable::new_write(reasons))
        } else {
            None
        };
        dps.push(certificate::DistributionPoint {
            crl_issuer,
            distribution_point,
            reasons,
        });
    }
    Ok(dps)
}

pub(crate) fn encode_extension(
    oid: &asn1::ObjectIdentifier<'_>,
    ext: &pyo3::PyAny,
) -> pyo3::PyResult<Option<Vec<u8>>> {
    if oid == &*oid::BASIC_CONSTRAINTS_OID {
        let bc = certificate::BasicConstraints {
            ca: ext.getattr("ca")?.extract::<bool>()?,
            path_length: ext.getattr("path_length")?.extract::<Option<u64>>()?,
        };
        Ok(Some(asn1::write_single(&bc)))
    } else if oid == &*oid::SUBJECT_KEY_IDENTIFIER_OID {
        Ok(Some(asn1::write_single(
            &ext.getattr("digest")?.extract::<&[u8]>()?,
        )))
    } else if oid == &*oid::KEY_USAGE_OID {
        let mut bs = [0, 0];
        certificate::set_bit(&mut bs, 0, ext.getattr("digital_signature")?.is_true()?);
        certificate::set_bit(&mut bs, 1, ext.getattr("content_commitment")?.is_true()?);
        certificate::set_bit(&mut bs, 2, ext.getattr("key_encipherment")?.is_true()?);
        certificate::set_bit(&mut bs, 3, ext.getattr("data_encipherment")?.is_true()?);
        certificate::set_bit(&mut bs, 4, ext.getattr("key_agreement")?.is_true()?);
        certificate::set_bit(&mut bs, 5, ext.getattr("key_cert_sign")?.is_true()?);
        certificate::set_bit(&mut bs, 6, ext.getattr("crl_sign")?.is_true()?);
        if ext.getattr("key_agreement")?.is_true()? {
            certificate::set_bit(&mut bs, 7, ext.getattr("encipher_only")?.is_true()?);
            certificate::set_bit(&mut bs, 8, ext.getattr("decipher_only")?.is_true()?);
        }
        let bits = if bs[1] == 0 { &bs[..1] } else { &bs[..] };
        let unused_bits = bits.last().unwrap().trailing_zeros() as u8;
        Ok(Some(asn1::write_single(&asn1::BitString::new(
            bits,
            unused_bits,
        ))))
    } else if oid == &*oid::AUTHORITY_INFORMATION_ACCESS_OID
        || oid == &*oid::SUBJECT_INFORMATION_ACCESS_OID
    {
        let ads = x509::common::encode_access_descriptions(ext.py(), ext)?;
        Ok(Some(asn1::write_single(&ads)))
    } else if oid == &*oid::EXTENDED_KEY_USAGE_OID {
        let mut oids = vec![];
        for el in ext.iter()? {
            let oid = asn1::ObjectIdentifier::from_string(
                el?.getattr("dotted_string")?.extract::<&str>()?,
            )
            .unwrap();
            oids.push(oid);
        }
        Ok(Some(asn1::write_single(&asn1::SequenceOfWriter::new(oids))))
    } else if oid == &*oid::CERTIFICATE_POLICIES_OID {
        let mut policy_informations = vec![];
        for py_policy_info in ext.iter()? {
            let py_policy_info = py_policy_info?;
            let py_policy_qualifiers = py_policy_info.getattr("policy_qualifiers")?;
            let qualifiers = if py_policy_qualifiers.is_true()? {
                let mut qualifiers = vec![];
                for py_qualifier in py_policy_qualifiers.iter()? {
                    let py_qualifier = py_qualifier?;
                    let qualifier = if py_qualifier.is_instance::<pyo3::types::PyString>()? {
                        let cps_uri = match asn1::IA5String::new(py_qualifier.extract()?) {
                            Some(s) => s,
                            None => {
                                return Err(pyo3::exceptions::PyValueError::new_err(
                                    "Qualifier must be an ASCII-string.",
                                ))
                            }
                        };
                        certificate::PolicyQualifierInfo {
                            policy_qualifier_id: (*oid::CP_CPS_URI_OID).clone(),
                            qualifier: certificate::Qualifier::CpsUri(cps_uri),
                        }
                    } else {
                        let py_notice = py_qualifier.getattr("notice_reference")?;
                        let notice_ref = if py_notice.is_true()? {
                            let mut notice_numbers = vec![];
                            for py_num in py_notice.getattr("notice_numbers")?.iter()? {
                                let bytes =
                                    py_uint_to_big_endian_bytes(ext.py(), py_num?.downcast()?)?;
                                notice_numbers.push(asn1::BigUint::new(bytes).unwrap());
                            }

                            Some(certificate::NoticeReference {
                                organization: certificate::DisplayText::Utf8String(
                                    asn1::Utf8String::new(
                                        py_notice.getattr("organization")?.extract()?,
                                    ),
                                ),
                                notice_numbers: x509::Asn1ReadableOrWritable::new_write(
                                    asn1::SequenceOfWriter::new(notice_numbers),
                                ),
                            })
                        } else {
                            None
                        };
                        let py_explicit_text = py_qualifier.getattr("explicit_text")?;
                        let explicit_text = if py_explicit_text.is_true()? {
                            Some(certificate::DisplayText::Utf8String(asn1::Utf8String::new(
                                py_explicit_text.extract()?,
                            )))
                        } else {
                            None
                        };

                        certificate::PolicyQualifierInfo {
                            policy_qualifier_id: (*oid::CP_USER_NOTICE_OID).clone(),
                            qualifier: certificate::Qualifier::UserNotice(
                                certificate::UserNotice {
                                    notice_ref,
                                    explicit_text,
                                },
                            ),
                        }
                    };
                    qualifiers.push(qualifier);
                }
                Some(x509::Asn1ReadableOrWritable::new_write(
                    asn1::SequenceOfWriter::new(qualifiers),
                ))
            } else {
                None
            };
            policy_informations.push(certificate::PolicyInformation {
                policy_identifier: asn1::ObjectIdentifier::from_string(
                    py_policy_info
                        .getattr("policy_identifier")?
                        .getattr("dotted_string")?
                        .extract()?,
                )
                .unwrap(),
                policy_qualifiers: qualifiers,
            });
        }
        Ok(Some(asn1::write_single(&asn1::SequenceOfWriter::new(
            policy_informations,
        ))))
    } else if oid == &*oid::POLICY_CONSTRAINTS_OID {
        let pc = certificate::PolicyConstraints {
            require_explicit_policy: ext.getattr("require_explicit_policy")?.extract()?,
            inhibit_policy_mapping: ext.getattr("inhibit_policy_mapping")?.extract()?,
        };
        Ok(Some(asn1::write_single(&pc)))
    } else if oid == &*oid::NAME_CONSTRAINTS_OID {
        let permitted = ext.getattr("permitted_subtrees")?;
        let excluded = ext.getattr("excluded_subtrees")?;
        let nc = certificate::NameConstraints {
            permitted_subtrees: encode_general_subtrees(ext.py(), permitted)?,
            excluded_subtrees: encode_general_subtrees(ext.py(), excluded)?,
        };
        Ok(Some(asn1::write_single(&nc)))
    } else if oid == &*oid::INHIBIT_ANY_POLICY_OID {
        let intval = ext
            .getattr("skip_certs")?
            .downcast::<pyo3::types::PyLong>()?;
        let bytes = py_uint_to_big_endian_bytes(ext.py(), intval)?;
        Ok(Some(asn1::write_single(
            &asn1::BigUint::new(bytes).unwrap(),
        )))
    } else if oid == &*oid::ISSUER_ALTERNATIVE_NAME_OID
        || oid == &*oid::SUBJECT_ALTERNATIVE_NAME_OID
    {
        let gns = x509::common::encode_general_names(ext.py(), ext)?;
        Ok(Some(asn1::write_single(&asn1::SequenceOfWriter::new(gns))))
    } else if oid == &*oid::AUTHORITY_KEY_IDENTIFIER_OID {
        let aki = encode_authority_key_identifier(ext.py(), ext)?;
        Ok(Some(asn1::write_single(&aki)))
    } else if oid == &*oid::FRESHEST_CRL_OID || oid == &*oid::CRL_DISTRIBUTION_POINTS_OID {
        let dps = encode_distribution_points(ext.py(), ext)?;
        Ok(Some(asn1::write_single(&asn1::SequenceOfWriter::new(dps))))
    } else if oid == &*oid::OCSP_NO_CHECK_OID {
        Ok(Some(asn1::write_single(&())))
    } else if oid == &*oid::TLS_FEATURE_OID {
        // Ideally we'd skip building up a vec and just write directly into the
        // writer. This isn't possible at the moment because the callback to write
        // an asn1::Sequence can't return an error, and we need to handle errors
        // from Python.
        let mut els = vec![];
        for el in ext.iter()? {
            els.push(el?.getattr("value")?.extract::<u64>()?);
        }

        Ok(Some(asn1::write_single(&asn1::SequenceOfWriter::new(els))))
    } else if oid == &*oid::PRECERT_POISON_OID {
        Ok(Some(asn1::write_single(&())))
    } else if oid == &*oid::PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID {
        let mut length = 0;
        for sct in ext.iter()? {
            let sct = sct?.downcast::<pyo3::PyCell<sct::Sct>>()?;
            length += sct.borrow().sct_data.len() + 2;
        }

        let mut result = vec![];
        result.extend_from_slice(&(length as u16).to_be_bytes());
        for sct in ext.iter()? {
            let sct = sct?.downcast::<pyo3::PyCell<sct::Sct>>()?;
            result.extend_from_slice(&(sct.borrow().sct_data.len() as u16).to_be_bytes());
            result.extend_from_slice(&sct.borrow().sct_data);
        }
        Ok(Some(asn1::write_single(&result.as_slice())))
    } else if oid == &*oid::CRL_REASON_OID {
        let value = ext
            .py()
            .import("cryptography.hazmat.backends.openssl.decode_asn1")?
            .getattr("_CRL_ENTRY_REASON_ENUM_TO_CODE")?
            .get_item(ext.getattr("reason")?)?
            .extract::<u32>()?;
        Ok(Some(asn1::write_single(&asn1::Enumerated::new(value))))
    } else if oid == &*oid::CERTIFICATE_ISSUER_OID {
        let gns = x509::common::encode_general_names(ext.py(), ext)?;
        Ok(Some(asn1::write_single(&asn1::SequenceOfWriter::new(gns))))
    } else if oid == &*oid::INVALIDITY_DATE_OID {
        let chrono_dt = x509::py_to_chrono(ext.getattr("invalidity_date")?)?;
        Ok(Some(asn1::write_single(&asn1::GeneralizedTime::new(
            chrono_dt,
        ))))
    } else if oid == &*oid::CRL_NUMBER_OID || oid == &*oid::DELTA_CRL_INDICATOR_OID {
        let intval = ext
            .getattr("crl_number")?
            .downcast::<pyo3::types::PyLong>()?;
        let bytes = py_uint_to_big_endian_bytes(ext.py(), intval)?;
        Ok(Some(asn1::write_single(
            &asn1::BigUint::new(bytes).unwrap(),
        )))
    } else if oid == &*oid::ISSUING_DISTRIBUTION_POINT_OID {
        let only_some_reasons = if ext.getattr("only_some_reasons")?.is_true()? {
            let py_reasons = ext.getattr("only_some_reasons")?;
            let reasons = certificate::encode_distribution_point_reasons(ext.py(), py_reasons)?;
            Some(x509::Asn1ReadableOrWritable::new_write(reasons))
        } else {
            None
        };
        let distribution_point = if ext.getattr("full_name")?.is_true()? {
            let gns = x509::common::encode_general_names(ext.py(), ext.getattr("full_name")?)?;
            Some(certificate::DistributionPointName::FullName(
                x509::Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(gns)),
            ))
        } else if ext.getattr("relative_name")?.is_true()? {
            let mut name_entries = vec![];
            for py_name_entry in ext.getattr("relative_name")?.iter()? {
                name_entries.push(x509::common::encode_name_entry(ext.py(), py_name_entry?)?);
            }
            Some(certificate::DistributionPointName::NameRelativeToCRLIssuer(
                x509::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(name_entries)),
            ))
        } else {
            None
        };

        let idp = crl::IssuingDistributionPoint {
            distribution_point,
            indirect_crl: ext.getattr("indirect_crl")?.extract()?,
            only_contains_attribute_certs: ext
                .getattr("only_contains_attribute_certs")?
                .extract()?,
            only_contains_ca_certs: ext.getattr("only_contains_ca_certs")?.extract()?,
            only_contains_user_certs: ext.getattr("only_contains_user_certs")?.extract()?,
            only_some_reasons,
        };
        Ok(Some(asn1::write_single(&idp)))
    } else if oid == &*oid::NONCE_OID {
        let nonce = ext.getattr("nonce")?.extract::<&[u8]>()?;
        Ok(Some(asn1::write_single(&nonce)))
    } else {
        Ok(None)
    }
}

pub(crate) fn add_to_module(_module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    Ok(())
}
