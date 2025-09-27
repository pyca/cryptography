// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::SimpleAsn1Readable;
use cryptography_x509::common::{
    Asn1ReadableOrWritable, AttributeTypeValue, AttributeValue, RawTlv,
};
use cryptography_x509::extensions::{
    AccessDescription, DuplicateExtensionsError, Extension, Extensions, RawExtensions,
};
use cryptography_x509::name::{GeneralName, Name, NameReadable, OtherName, UnvalidatedIA5String};
use pyo3::types::{IntoPyDict, PyAnyMethods, PyListMethods, PyTzInfoAccess};

use crate::asn1::{oid_to_py_oid, py_oid_to_oid};
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types, x509};

/// Parse all sections in a PEM file and return the first matching section.
/// If no matching sections are found, return an error.
pub(crate) fn find_in_pem(
    data: &[u8],
    filter_fn: fn(&pem::Pem) -> bool,
    no_match_err: &'static str,
) -> Result<pem::Pem, CryptographyError> {
    let all_sections = pem::parse_many(data)?;
    if all_sections.is_empty() {
        return Err(CryptographyError::from(pem::PemError::MalformedFraming));
    }
    all_sections.into_iter().find(filter_fn).ok_or_else(|| {
        CryptographyError::from(pyo3::exceptions::PyValueError::new_err(no_match_err))
    })
}

pub(crate) fn encode_name<'p>(
    py: pyo3::Python<'_>,
    ka: &'p cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedBytes>,
    py_name: &pyo3::Bound<'_, pyo3::PyAny>,
) -> pyo3::PyResult<Name<'p>> {
    let mut rdns = vec![];

    for py_rdn in py_name.getattr(pyo3::intern!(py, "rdns"))?.try_iter()? {
        let py_rdn = py_rdn?;
        let mut attrs = vec![];

        for py_attr in py_rdn.try_iter()? {
            attrs.push(encode_name_entry(py, ka, &py_attr?)?);
        }
        rdns.push(asn1::SetOfWriter::new(attrs));
    }
    Ok(Asn1ReadableOrWritable::new_write(
        asn1::SequenceOfWriter::new(rdns),
    ))
}

pub(crate) fn encode_name_entry<'p>(
    py: pyo3::Python<'_>,
    ka: &'p cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedBytes>,
    py_name_entry: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<AttributeTypeValue<'p>> {
    let attr_type = py_name_entry.getattr(pyo3::intern!(py, "_type"))?;
    let tag = attr_type
        .getattr(pyo3::intern!(py, "value"))?
        .extract::<u8>()?;
    let raw_value = py_name_entry.getattr(pyo3::intern!(py, "value"))?;
    let value = if attr_type.is(&types::ASN1_TYPE_BIT_STRING.get(py)?) {
        AttributeValue::AnyString(RawTlv::new(
            asn1::BitString::TAG,
            ka.add(raw_value.extract()?),
        ))
    } else if attr_type.is(&types::ASN1_TYPE_BMP_STRING.get(py)?) {
        AttributeValue::BmpString(
            asn1::BMPString::new(
                ka.add(
                    raw_value
                        .call_method1(pyo3::intern!(py, "encode"), ("utf_16_be",))?
                        .extract()?,
                ),
            )
            .unwrap(),
        )
    } else if attr_type.is(&types::ASN1_TYPE_UNIVERSAL_STRING.get(py)?) {
        AttributeValue::UniversalString(
            asn1::UniversalString::new(
                ka.add(
                    raw_value
                        .call_method1(pyo3::intern!(py, "encode"), ("utf_32_be",))?
                        .extract()?,
                ),
            )
            .unwrap(),
        )
    } else {
        AttributeValue::AnyString(RawTlv::new(
            asn1::Tag::from_bytes(&[tag])?.0,
            ka.add(
                raw_value
                    .call_method1(pyo3::intern!(py, "encode"), ("utf8",))?
                    .extract()?,
            ),
        ))
    };
    let py_oid = py_name_entry.getattr(pyo3::intern!(py, "oid"))?;
    let oid = py_oid_to_oid(py_oid)?;

    Ok(AttributeTypeValue {
        type_id: oid,
        value,
    })
}

#[pyo3::pyfunction]
pub(crate) fn encode_name_bytes<'p>(
    py: pyo3::Python<'p>,
    py_name: &pyo3::Bound<'p, pyo3::PyAny>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let ka = cryptography_keepalive::KeepAlive::new();
    let name = encode_name(py, &ka, py_name)?;
    let result = asn1::write_single(&name)?;
    Ok(pyo3::types::PyBytes::new(py, &result))
}

pub(crate) fn encode_general_names<'a>(
    py: pyo3::Python<'_>,
    ka_bytes: &'a cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedBytes>,
    ka_str: &'a cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedStr>,
    py_gns: &pyo3::Bound<'a, pyo3::PyAny>,
) -> Result<Vec<GeneralName<'a>>, CryptographyError> {
    let mut gns = vec![];
    for el in py_gns.try_iter()? {
        let gn = encode_general_name(py, ka_bytes, ka_str, &el?)?;
        gns.push(gn);
    }
    Ok(gns)
}

pub(crate) fn encode_general_name<'a>(
    py: pyo3::Python<'_>,
    ka_bytes: &'a cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedBytes>,
    ka_str: &'a cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedStr>,
    gn: &pyo3::Bound<'a, pyo3::PyAny>,
) -> Result<GeneralName<'a>, CryptographyError> {
    let gn_type = gn.get_type();
    let gn_value = gn.getattr(pyo3::intern!(py, "value"))?;

    if gn_type.is(&types::DNS_NAME.get(py)?) {
        Ok(GeneralName::DNSName(UnvalidatedIA5String(
            ka_str.add(gn_value.extract()?),
        )))
    } else if gn_type.is(&types::RFC822_NAME.get(py)?) {
        Ok(GeneralName::RFC822Name(UnvalidatedIA5String(
            ka_str.add(gn_value.extract()?),
        )))
    } else if gn_type.is(&types::DIRECTORY_NAME.get(py)?) {
        let name = encode_name(py, ka_bytes, &gn_value)?;
        Ok(GeneralName::DirectoryName(name))
    } else if gn_type.is(&types::OTHER_NAME.get(py)?) {
        let py_oid = gn.getattr(pyo3::intern!(py, "type_id"))?;
        Ok(GeneralName::OtherName(OtherName {
            type_id: py_oid_to_oid(py_oid)?,
            value: asn1::parse_single(ka_bytes.add(gn_value.extract()?)).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "OtherName value must be valid DER: {e:?}"
                ))
            })?,
        }))
    } else if gn_type.is(&types::UNIFORM_RESOURCE_IDENTIFIER.get(py)?) {
        Ok(GeneralName::UniformResourceIdentifier(
            UnvalidatedIA5String(ka_str.add(gn_value.extract()?)),
        ))
    } else if gn_type.is(&types::IP_ADDRESS.get(py)?) {
        Ok(GeneralName::IPAddress(ka_bytes.add(
            gn.call_method0(pyo3::intern!(py, "_packed"))?.extract()?,
        )))
    } else if gn_type.is(&types::REGISTERED_ID.get(py)?) {
        let oid = py_oid_to_oid(gn_value)?;
        Ok(GeneralName::RegisteredID(oid))
    } else {
        Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Unsupported GeneralName type"),
        ))
    }
}

pub(crate) fn encode_access_descriptions<'a>(
    py: pyo3::Python<'a>,
    py_ads: &pyo3::Bound<'a, pyo3::PyAny>,
) -> CryptographyResult<Vec<u8>> {
    let mut ads = vec![];
    let ka_bytes = cryptography_keepalive::KeepAlive::new();
    let ka_str = cryptography_keepalive::KeepAlive::new();
    for py_ad in py_ads.try_iter()? {
        let py_ad = py_ad?;
        let py_oid = py_ad.getattr(pyo3::intern!(py, "access_method"))?;
        let access_method = py_oid_to_oid(py_oid)?;
        let py_access_location = py_ad.getattr(pyo3::intern!(py, "access_location"))?;
        let access_location = encode_general_name(py, &ka_bytes, &ka_str, &py_access_location)?;
        ads.push(AccessDescription {
            access_method,
            access_location,
        });
    }
    Ok(asn1::write_single(&asn1::SequenceOfWriter::new(ads))?)
}

pub(crate) fn parse_name<'p>(
    py: pyo3::Python<'p>,
    name: &NameReadable<'_>,
) -> Result<pyo3::Bound<'p, pyo3::PyAny>, CryptographyError> {
    let py_rdns = pyo3::types::PyList::empty(py);
    for rdn in name.clone() {
        let py_rdn = parse_rdn(py, &rdn)?;
        py_rdns.append(py_rdn)?;
    }
    Ok(types::NAME.get(py)?.call1((py_rdns,))?)
}

fn parse_name_attribute<'p>(
    py: pyo3::Python<'p>,
    attribute: AttributeTypeValue<'_>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let oid = oid_to_py_oid(py, &attribute.type_id)?;
    let tag_val = attribute.value.tag().as_u8().ok_or_else(|| {
        CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
            "Long-form tags are not supported in NameAttribute values",
        ))
    })?;
    let py_tag = types::ASN1_TYPE_TO_ENUM.get(py)?.get_item(tag_val)?;
    let py_data = match attribute.value {
        AttributeValue::AnyString(s) => {
            if s.tag() == asn1::BitString::TAG {
                pyo3::types::PyBytes::new(py, s.data()).into_any()
            } else {
                let parsed = std::str::from_utf8(s.data())
                    .map_err(|_| asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue))?;
                pyo3::types::PyString::new(py, parsed).into_any()
            }
        }
        AttributeValue::PrintableString(printable_string) => {
            pyo3::types::PyString::new(py, printable_string.as_str()).into_any()
        }
        AttributeValue::UniversalString(universal_string) => {
            let py_bytes = pyo3::types::PyBytes::new(py, universal_string.as_utf32_be_bytes());
            py_bytes.call_method1(pyo3::intern!(py, "decode"), ("utf_32_be",))?
        }
        AttributeValue::BmpString(bmp_string) => {
            let py_bytes = pyo3::types::PyBytes::new(py, bmp_string.as_utf16_be_bytes());
            py_bytes.call_method1(pyo3::intern!(py, "decode"), ("utf_16_be",))?
        }
    };
    let kwargs = [(pyo3::intern!(py, "_validate"), false)].into_py_dict(py)?;
    Ok(types::NAME_ATTRIBUTE
        .get(py)?
        .call((oid, py_data, py_tag), Some(&kwargs))?)
}

pub(crate) fn parse_rdn<'a>(
    py: pyo3::Python<'a>,
    rdn: &asn1::SetOf<'a, AttributeTypeValue<'a>>,
) -> CryptographyResult<pyo3::Bound<'a, pyo3::PyAny>> {
    let py_attrs = pyo3::types::PyList::empty(py);
    for attribute in rdn.clone() {
        let na = parse_name_attribute(py, attribute)?;
        py_attrs.append(na)?;
    }
    Ok(types::RELATIVE_DISTINGUISHED_NAME
        .get(py)?
        .call1((py_attrs,))?)
}

pub(crate) fn parse_general_name<'p>(
    py: pyo3::Python<'p>,
    gn: GeneralName<'_>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let py_gn = match gn {
        GeneralName::OtherName(data) => {
            let oid = oid_to_py_oid(py, &data.type_id)?;
            types::OTHER_NAME
                .get(py)?
                .call1((oid, data.value.full_data()))?
        }
        GeneralName::RFC822Name(data) => types::RFC822_NAME
            .get(py)?
            .call_method1(pyo3::intern!(py, "_init_without_validation"), (data.0,))?,
        GeneralName::DNSName(data) => types::DNS_NAME
            .get(py)?
            .call_method1(pyo3::intern!(py, "_init_without_validation"), (data.0,))?,
        GeneralName::DirectoryName(data) => {
            let py_name = parse_name(py, data.unwrap_read())?;
            types::DIRECTORY_NAME.get(py)?.call1((py_name,))?
        }
        GeneralName::UniformResourceIdentifier(data) => types::UNIFORM_RESOURCE_IDENTIFIER
            .get(py)?
            .call_method1(pyo3::intern!(py, "_init_without_validation"), (data.0,))?,
        GeneralName::IPAddress(data) => {
            if data.len() == 4 || data.len() == 16 {
                let addr = types::IPADDRESS_IPADDRESS.get(py)?.call1((data,))?;
                types::IP_ADDRESS.get(py)?.call1((addr,))?
            } else {
                // if it's not an IPv4 or IPv6 we assume it's an IPNetwork and
                // verify length in this function.
                create_ip_network(py, data)?
            }
        }
        GeneralName::RegisteredID(data) => {
            let oid = oid_to_py_oid(py, &data)?;
            types::REGISTERED_ID.get(py)?.call1((oid,))?
        }
        _ => {
            return Err(CryptographyError::from(
                exceptions::UnsupportedGeneralNameType::new_err(
                    "x400Address/EDIPartyName are not supported types",
                ),
            ))
        }
    };
    Ok(py_gn)
}

pub(crate) fn parse_general_names<'a>(
    py: pyo3::Python<'a>,
    gn_seq: &asn1::SequenceOf<'a, GeneralName<'a>>,
) -> CryptographyResult<pyo3::Bound<'a, pyo3::PyAny>> {
    let gns = pyo3::types::PyList::empty(py);
    for gn in gn_seq.clone() {
        let py_gn = parse_general_name(py, gn)?;
        gns.append(py_gn)?;
    }
    Ok(gns.into_any())
}

fn create_ip_network<'p>(
    py: pyo3::Python<'p>,
    data: &[u8],
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let prefix = match data.len() {
        8 => {
            let num = u32::from_be_bytes(data[4..].try_into().unwrap());
            ipv4_netmask(num)
        }
        32 => {
            let num = u128::from_be_bytes(data[16..].try_into().unwrap());
            ipv6_netmask(num)
        }
        _ => Err(CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
            format!("Invalid IPNetwork, must be 8 bytes for IPv4 and 32 bytes for IPv6. Found length: {}", data.len()),
        ))),
    };
    let base = types::IPADDRESS_IPADDRESS
        .get(py)?
        .call1((pyo3::types::PyBytes::new(py, &data[..data.len() / 2]),))?;
    let net = format!(
        "{}/{}",
        base.getattr(pyo3::intern!(py, "exploded"))?
            .extract::<pyo3::pybacked::PyBackedStr>()?,
        prefix?
    );
    let addr = types::IPADDRESS_IPNETWORK.get(py)?.call1((net,))?;
    Ok(types::IP_ADDRESS.get(py)?.call1((addr,))?)
}

fn ipv4_netmask(num: u32) -> Result<u32, CryptographyError> {
    if num.leading_ones() + num.trailing_zeros() != 32 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Invalid netmask"),
        ));
    }
    Ok((!num).leading_zeros())
}

fn ipv6_netmask(num: u128) -> Result<u32, CryptographyError> {
    if num.leading_ones() + num.trailing_zeros() != 128 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Invalid netmask"),
        ));
    }
    Ok((!num).leading_zeros())
}

pub(crate) fn parse_and_cache_extensions<
    'p,
    F: Fn(&Extension<'p>) -> Result<Option<pyo3::Bound<'p, pyo3::PyAny>>, CryptographyError>,
>(
    py: pyo3::Python<'p>,
    cached_extensions: &pyo3::sync::PyOnceLock<pyo3::Py<pyo3::PyAny>>,
    raw_extensions: &Option<RawExtensions<'p>>,
    parse_ext: F,
) -> pyo3::PyResult<pyo3::Py<pyo3::PyAny>> {
    cached_extensions
        .get_or_try_init(py, || {
            let extensions = match Extensions::from_raw_extensions(raw_extensions.as_ref()) {
                Ok(extensions) => extensions,
                Err(DuplicateExtensionsError(oid)) => {
                    let oid_obj = oid_to_py_oid(py, &oid)?;
                    return Err(exceptions::DuplicateExtension::new_err((
                        format!("Duplicate {} extension found", &oid),
                        oid_obj.unbind(),
                    )));
                }
            };

            let exts = pyo3::types::PyList::empty(py);
            for raw_ext in extensions.iter() {
                let oid_obj = oid_to_py_oid(py, &raw_ext.extn_id)?;

                let extn_value = match parse_ext(&raw_ext)? {
                    Some(e) => e,
                    None => types::UNRECOGNIZED_EXTENSION
                        .get(py)?
                        .call1((oid_obj.clone(), raw_ext.extn_value))?,
                };
                let ext_obj =
                    types::EXTENSION
                        .get(py)?
                        .call1((oid_obj, raw_ext.critical, extn_value))?;
                exts.append(ext_obj)?;
            }
            Ok(types::EXTENSIONS.get(py)?.call1((exts,))?.unbind())
        })
        .map(|p| p.clone_ref(py))
}

pub(crate) fn encode_extensions<
    'p,
    F: Fn(
        pyo3::Python<'_>,
        &asn1::ObjectIdentifier,
        &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<Option<Vec<u8>>>,
>(
    py: pyo3::Python<'p>,
    ka_vec: &'p cryptography_keepalive::KeepAlive<Vec<u8>>,
    ka_bytes: &'p cryptography_keepalive::KeepAlive<pyo3::pybacked::PyBackedBytes>,
    py_exts: &pyo3::Bound<'p, pyo3::PyAny>,
    encode_ext: F,
) -> pyo3::PyResult<Option<RawExtensions<'p>>> {
    let mut exts = vec![];
    for py_ext in py_exts.try_iter()? {
        let py_ext = py_ext?;
        let py_oid = py_ext.getattr(pyo3::intern!(py, "oid"))?;
        let oid = py_oid_to_oid(py_oid)?;

        let ext_val = py_ext.getattr(pyo3::intern!(py, "value"))?;
        if ext_val.is_instance(&types::UNRECOGNIZED_EXTENSION.get(py)?)? {
            exts.push(Extension {
                extn_id: oid,
                critical: py_ext.getattr(pyo3::intern!(py, "critical"))?.extract()?,
                extn_value: ka_bytes.add(ext_val.getattr(pyo3::intern!(py, "value"))?.extract()?),
            });
            continue;
        }
        match encode_ext(py, &oid, &ext_val)? {
            Some(data) => {
                exts.push(Extension {
                    extn_id: oid,
                    critical: py_ext.getattr(pyo3::intern!(py, "critical"))?.extract()?,
                    extn_value: ka_vec.add(data),
                });
            }
            None => {
                return Err(pyo3::exceptions::PyNotImplementedError::new_err(format!(
                    "Extension not supported: {oid}"
                )))
            }
        }
    }
    if exts.is_empty() {
        return Ok(None);
    }
    Ok(Some(Asn1ReadableOrWritable::new_write(
        asn1::SequenceOfWriter::new(exts),
    )))
}

#[pyo3::pyfunction]
pub(crate) fn encode_extension_value<'p>(
    py: pyo3::Python<'p>,
    py_ext: pyo3::Bound<'p, pyo3::PyAny>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let oid = py_oid_to_oid(py_ext.getattr(pyo3::intern!(py, "oid"))?)?;

    if let Some(data) = x509::extensions::encode_extension(py, &oid, &py_ext)? {
        // TODO: extra copy
        let py_data = pyo3::types::PyBytes::new(py, &data);
        return Ok(py_data);
    }

    Err(pyo3::exceptions::PyNotImplementedError::new_err(format!(
        "Extension not supported: {oid}"
    )))
}

pub(crate) fn datetime_to_py<'p>(
    py: pyo3::Python<'p>,
    dt: &asn1::DateTime,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let py_datetime = pyo3::types::PyDateTime::new(
        py,
        dt.year().into(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        0,
        None,
    )?;
    Ok(py_datetime.into_any())
}

pub(crate) fn datetime_to_py_utc_with_microseconds<'p>(
    py: pyo3::Python<'p>,
    dt: &asn1::DateTime,
    microseconds: u32,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let py_datetime = pyo3::types::PyDateTime::new(
        py,
        dt.year().into(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        microseconds,
        Some(&pyo3::types::PyTzInfo::utc(py)?.to_owned()),
    )?;
    Ok(py_datetime.into_any())
}

pub(crate) fn datetime_to_py_utc<'p>(
    py: pyo3::Python<'p>,
    dt: &asn1::DateTime,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    datetime_to_py_utc_with_microseconds(py, dt, 0)
}

// Convert Python's datetime objects to a tuple of `asn1::DateTime` and
// microseconds.
pub(crate) fn py_to_datetime_with_microseconds(
    py: pyo3::Python<'_>,
    val: &pyo3::Bound<'_, pyo3::types::PyDateTime>,
) -> pyo3::PyResult<(asn1::DateTime, Option<u32>)> {
    // We treat naive datetimes as UTC times, while aware datetimes get
    // normalized to UTC before conversion.
    let normalized: pyo3::Bound<'_, pyo3::types::PyAny>;
    let val_utc = if val.get_tzinfo().is_none() {
        val.as_any()
    } else {
        let utc = pyo3::types::PyTzInfo::utc(py)?;
        normalized = val.call_method1(pyo3::intern!(py, "astimezone"), (utc,))?;
        &normalized
    };

    let datetime = asn1::DateTime::new(
        val_utc.getattr(pyo3::intern!(py, "year"))?.extract()?,
        val_utc.getattr(pyo3::intern!(py, "month"))?.extract()?,
        val_utc.getattr(pyo3::intern!(py, "day"))?.extract()?,
        val_utc.getattr(pyo3::intern!(py, "hour"))?.extract()?,
        val_utc.getattr(pyo3::intern!(py, "minute"))?.extract()?,
        val_utc.getattr(pyo3::intern!(py, "second"))?.extract()?,
    )
    .unwrap();

    let microseconds: u32 = val_utc
        .getattr(pyo3::intern!(py, "microsecond"))?
        .extract()?;
    let microseconds = if microseconds > 0 {
        Some(microseconds)
    } else {
        None
    };
    Ok((datetime, microseconds))
}

pub(crate) fn py_to_datetime(
    py: pyo3::Python<'_>,
    val: pyo3::Bound<'_, pyo3::types::PyDateTime>,
) -> pyo3::PyResult<asn1::DateTime> {
    let (datetime, _) = py_to_datetime_with_microseconds(py, &val)?;
    Ok(datetime)
}

pub(crate) fn datetime_now(py: pyo3::Python<'_>) -> pyo3::PyResult<asn1::DateTime> {
    let utc = pyo3::types::PyTzInfo::utc(py)?;

    py_to_datetime(
        py,
        types::DATETIME_DATETIME
            .get(py)?
            .call_method1(pyo3::intern!(py, "now"), (utc,))?
            .extract()?,
    )
}
