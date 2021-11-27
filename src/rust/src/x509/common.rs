// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::PyAsn1Error;
use crate::x509;
use chrono::{Datelike, TimeZone, Timelike};
use pyo3::types::IntoPyDict;
use pyo3::ToPyObject;
use std::collections::HashSet;
use std::convert::TryInto;
use std::marker::PhantomData;

/// parse all sections in a PEM file and return the only matching section.
/// If no or multiple matching sections are found, return an error.
pub(crate) fn find_in_pem(
    data: &[u8],
    filter_fn: fn(&pem::Pem) -> bool,
    no_match_err: &'static str,
) -> Result<pem::Pem, PyAsn1Error> {
    let all_sections = pem::parse_many(data)?;
    if all_sections.is_empty() {
        return Err(PyAsn1Error::from(pem::PemError::MalformedFraming));
    }
    all_sections
        .into_iter()
        .find(filter_fn)
        .ok_or_else(|| PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(no_match_err)))
}

pub(crate) type Name<'a> = Asn1ReadableOrWritable<
    'a,
    asn1::SequenceOf<'a, asn1::SetOf<'a, AttributeTypeValue<'a>>>,
    asn1::SequenceOfWriter<
        'a,
        asn1::SetOfWriter<'a, AttributeTypeValue<'a>, Vec<AttributeTypeValue<'a>>>,
        Vec<asn1::SetOfWriter<'a, AttributeTypeValue<'a>, Vec<AttributeTypeValue<'a>>>>,
    >,
>;

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone)]
pub(crate) struct AttributeTypeValue<'a> {
    pub(crate) type_id: asn1::ObjectIdentifier<'a>,
    pub(crate) value: RawTlv<'a>,
}

// Like `asn1::Tlv` but doesn't store `full_data` so it can be constucted from
// an un-encoded tag and value.
#[derive(Hash, PartialEq, Clone)]
pub(crate) struct RawTlv<'a> {
    tag: u8,
    value: &'a [u8],
}

impl<'a> RawTlv<'a> {
    pub(crate) fn new(tag: u8, value: &'a [u8]) -> Self {
        RawTlv { tag, value }
    }

    pub(crate) fn tag(&self) -> u8 {
        self.tag
    }
    pub(crate) fn data(&self) -> &'a [u8] {
        self.value
    }
}
impl<'a> asn1::Asn1Readable<'a> for RawTlv<'a> {
    fn parse(parser: &mut asn1::Parser<'a>) -> asn1::ParseResult<Self> {
        let tlv = parser.read_element::<asn1::Tlv<'a>>()?;
        Ok(RawTlv::new(tlv.tag(), tlv.data()))
    }

    fn can_parse(_tag: u8) -> bool {
        true
    }
}
impl<'a> asn1::Asn1Writable<'a> for RawTlv<'a> {
    fn write(&self, w: &mut asn1::Writer<'_>) {
        w.write_tlv(self.tag, move |dest| dest.extend_from_slice(self.value))
    }
}

pub(crate) fn encode_name<'p>(
    py: pyo3::Python<'p>,
    py_name: &'p pyo3::PyAny,
) -> pyo3::PyResult<Name<'p>> {
    let mut rdns = vec![];

    for py_rdn in py_name.getattr("rdns")?.iter()? {
        let py_rdn = py_rdn?;
        let mut attrs = vec![];

        for py_attr in py_rdn.iter()? {
            attrs.push(encode_name_entry(py, py_attr?)?);
        }
        rdns.push(asn1::SetOfWriter::new(attrs));
    }
    Ok(Asn1ReadableOrWritable::new_write(
        asn1::SequenceOfWriter::new(rdns),
    ))
}

pub(crate) fn encode_name_entry<'p>(
    py: pyo3::Python<'p>,
    py_name_entry: &'p pyo3::PyAny,
) -> pyo3::PyResult<AttributeTypeValue<'p>> {
    let asn1_type = py.import("cryptography.x509.name")?.getattr("_ASN1Type")?;

    let attr_type = py_name_entry.getattr("_type")?;
    let tag = attr_type.getattr("value")?.extract::<u8>()?;
    let encoding = if attr_type == asn1_type.getattr("BMPString")? {
        "utf_16_be"
    } else if attr_type == asn1_type.getattr("UniversalString")? {
        "utf_32_be"
    } else {
        "utf8"
    };
    let value = py_name_entry
        .getattr("value")?
        .call_method1("encode", (encoding,))?
        .extract()?;
    let oid = asn1::ObjectIdentifier::from_string(
        py_name_entry
            .getattr("oid")?
            .getattr("dotted_string")?
            .extract::<&str>()?,
    )
    .unwrap();

    Ok(AttributeTypeValue {
        type_id: oid,
        value: RawTlv::new(tag, value),
    })
}

#[pyo3::prelude::pyfunction]
fn encode_name_bytes<'p>(
    py: pyo3::Python<'p>,
    py_name: &'p pyo3::PyAny,
) -> pyo3::PyResult<&'p pyo3::types::PyBytes> {
    let name = encode_name(py, py_name)?;
    let result = asn1::write_single(&name);
    Ok(pyo3::types::PyBytes::new(py, &result))
}

pub(crate) struct UnvalidatedIA5String<'a>(pub(crate) &'a str);

impl<'a> asn1::SimpleAsn1Readable<'a> for UnvalidatedIA5String<'a> {
    const TAG: u8 = 0x16;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        Ok(UnvalidatedIA5String(std::str::from_utf8(data).map_err(
            |_| asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue),
        )?))
    }
}

impl<'a> asn1::SimpleAsn1Writable<'a> for UnvalidatedIA5String<'a> {
    const TAG: u8 = 0x16;
    fn write_data(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(self.0.as_bytes());
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash)]
pub(crate) struct OtherName<'a> {
    pub(crate) type_id: asn1::ObjectIdentifier<'a>,
    #[explicit(0, required)]
    pub(crate) value: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) enum GeneralName<'a> {
    #[implicit(0)]
    OtherName(OtherName<'a>),

    #[implicit(1)]
    RFC822Name(UnvalidatedIA5String<'a>),

    #[implicit(2)]
    DNSName(UnvalidatedIA5String<'a>),

    #[implicit(3)]
    // unsupported
    X400Address(asn1::Sequence<'a>),

    // Name is explicit per RFC 5280 Appendix A.1.
    #[explicit(4)]
    DirectoryName(Name<'a>),

    #[implicit(5)]
    // unsupported
    EDIPartyName(asn1::Sequence<'a>),

    #[implicit(6)]
    UniformResourceIdentifier(UnvalidatedIA5String<'a>),

    #[implicit(7)]
    IPAddress(&'a [u8]),

    #[implicit(8)]
    RegisteredID(asn1::ObjectIdentifier<'a>),
}

pub(crate) type SequenceOfGeneralName<'a> = Asn1ReadableOrWritable<
    'a,
    asn1::SequenceOf<'a, GeneralName<'a>>,
    asn1::SequenceOfWriter<'a, GeneralName<'a>, Vec<GeneralName<'a>>>,
>;

pub(crate) fn encode_general_names<'a>(
    py: pyo3::Python<'a>,
    py_gns: &'a pyo3::PyAny,
) -> Result<Vec<GeneralName<'a>>, PyAsn1Error> {
    let mut gns = vec![];
    for el in py_gns.iter()? {
        let gn = encode_general_name(py, el?)?;
        gns.push(gn)
    }
    Ok(gns)
}

pub(crate) fn encode_general_name<'a>(
    py: pyo3::Python<'a>,
    gn: &'a pyo3::PyAny,
) -> Result<GeneralName<'a>, PyAsn1Error> {
    let gn_module = py.import("cryptography.x509.general_name")?;
    let gn_type = gn.get_type().as_ref();
    let gn_value = gn.getattr("value")?;
    if gn_type == gn_module.getattr("DNSName")? {
        Ok(GeneralName::DNSName(UnvalidatedIA5String(
            gn_value.extract::<&str>()?,
        )))
    } else if gn_type == gn_module.getattr("RFC822Name")? {
        Ok(GeneralName::RFC822Name(UnvalidatedIA5String(
            gn_value.extract::<&str>()?,
        )))
    } else if gn_type == gn_module.getattr("DirectoryName")? {
        let name = encode_name(py, gn_value)?;
        Ok(GeneralName::DirectoryName(name))
    } else if gn_type == gn_module.getattr("OtherName")? {
        Ok(GeneralName::OtherName(OtherName {
            type_id: asn1::ObjectIdentifier::from_string(
                gn.getattr("type_id")?
                    .getattr("dotted_string")?
                    .extract::<&str>()?,
            )
            .unwrap(),
            value: asn1::parse_single(gn_value.extract::<&[u8]>()?)?,
        }))
    } else if gn_type == gn_module.getattr("UniformResourceIdentifier")? {
        Ok(GeneralName::UniformResourceIdentifier(
            UnvalidatedIA5String(gn_value.extract::<&str>()?),
        ))
    } else if gn_type == gn_module.getattr("IPAddress")? {
        Ok(GeneralName::IPAddress(
            gn.call_method0("_packed")?.extract::<&[u8]>()?,
        ))
    } else if gn_type == gn_module.getattr("RegisteredID")? {
        let oid = asn1::ObjectIdentifier::from_string(
            gn_value.getattr("dotted_string")?.extract::<&str>()?,
        )
        .unwrap();
        Ok(GeneralName::RegisteredID(oid))
    } else {
        Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            "Unsupported GeneralName type",
        )))
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct AccessDescription<'a> {
    pub(crate) access_method: asn1::ObjectIdentifier<'a>,
    pub(crate) access_location: GeneralName<'a>,
}

pub(crate) type SequenceOfAccessDescriptions<'a> = Asn1ReadableOrWritable<
    'a,
    asn1::SequenceOf<'a, AccessDescription<'a>>,
    asn1::SequenceOfWriter<'a, AccessDescription<'a>, Vec<AccessDescription<'a>>>,
>;

pub(crate) fn encode_access_descriptions<'a>(
    py: pyo3::Python<'a>,
    py_ads: &'a pyo3::PyAny,
) -> Result<SequenceOfAccessDescriptions<'a>, PyAsn1Error> {
    let mut ads = vec![];
    for py_ad in py_ads.iter()? {
        let py_ad = py_ad?;
        let access_method = asn1::ObjectIdentifier::from_string(
            py_ad
                .getattr("access_method")?
                .getattr("dotted_string")?
                .extract::<&str>()?,
        )
        .unwrap();
        let access_location = encode_general_name(py, py_ad.getattr("access_location")?)?;
        ads.push(AccessDescription {
            access_method,
            access_location,
        });
    }
    Ok(Asn1ReadableOrWritable::new_write(
        asn1::SequenceOfWriter::new(ads),
    ))
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone)]
pub(crate) enum Time {
    UtcTime(asn1::UtcTime),
    GeneralizedTime(asn1::GeneralizedTime),
}

impl Time {
    pub(crate) fn as_chrono(&self) -> &chrono::DateTime<chrono::Utc> {
        match self {
            Time::UtcTime(data) => data.as_chrono(),
            Time::GeneralizedTime(data) => data.as_chrono(),
        }
    }
}

pub(crate) type Extensions<'a> = Asn1ReadableOrWritable<
    'a,
    asn1::SequenceOf<'a, Extension<'a>>,
    asn1::SequenceOfWriter<'a, Extension<'a>, Vec<Extension<'a>>>,
>;

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone)]
pub(crate) struct AlgorithmIdentifier<'a> {
    pub(crate) oid: asn1::ObjectIdentifier<'a>,
    pub(crate) params: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone)]
pub(crate) struct Extension<'a> {
    pub(crate) extn_id: asn1::ObjectIdentifier<'a>,
    #[default(false)]
    pub(crate) critical: bool,
    pub(crate) extn_value: &'a [u8],
}

pub(crate) fn parse_name<'p>(
    py: pyo3::Python<'p>,
    name: &Name<'_>,
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    let x509_module = py.import("cryptography.x509")?;
    let py_rdns = pyo3::types::PyList::empty(py);
    for rdn in name.unwrap_read().clone() {
        let py_rdn = parse_rdn(py, &rdn)?;
        py_rdns.append(py_rdn)?;
    }
    x509_module.call_method1("Name", (py_rdns,))
}

fn parse_name_attribute(
    py: pyo3::Python<'_>,
    attribute: AttributeTypeValue<'_>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let oid = x509_module
        .call_method1("ObjectIdentifier", (attribute.type_id.to_string(),))?
        .to_object(py);
    let tag_enum = py
        .import("cryptography.x509.name")?
        .getattr("_ASN1_TYPE_TO_ENUM")?;
    let py_tag = tag_enum.get_item(attribute.value.tag().to_object(py))?;
    let py_data = match attribute.value.tag() {
        // BMPString tag value
        30 => {
            let py_bytes = pyo3::types::PyBytes::new(py, attribute.value.data());
            py_bytes
                .call_method1("decode", ("utf_16_be",))?
                .extract::<&str>()?
        }
        // UniversalString
        28 => {
            let py_bytes = pyo3::types::PyBytes::new(py, attribute.value.data());
            py_bytes
                .call_method1("decode", ("utf_32_be",))?
                .extract::<&str>()?
        }
        _ => std::str::from_utf8(attribute.value.data())
            .map_err(|_| asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue))?,
    };
    let kwargs = [("_validate", false)].into_py_dict(py);
    Ok(x509_module
        .call_method("NameAttribute", (oid, py_data, py_tag), Some(kwargs))?
        .to_object(py))
}

pub(crate) fn parse_rdn<'a>(
    py: pyo3::Python<'_>,
    rdn: &asn1::SetOf<'a, AttributeTypeValue<'a>>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let py_attrs = pyo3::types::PySet::empty(py)?;
    for attribute in rdn.clone() {
        let na = parse_name_attribute(py, attribute)?;
        py_attrs.add(na)?;
    }
    Ok(x509_module
        .call_method1("RelativeDistinguishedName", (py_attrs,))?
        .to_object(py))
}

pub(crate) fn parse_general_name(
    py: pyo3::Python<'_>,
    gn: GeneralName<'_>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let py_gn = match gn {
        GeneralName::OtherName(data) => {
            let oid = x509_module
                .call_method1("ObjectIdentifier", (data.type_id.to_string(),))?
                .to_object(py);
            x509_module
                .call_method1("OtherName", (oid, data.value.full_data()))?
                .to_object(py)
        }
        GeneralName::RFC822Name(data) => x509_module
            .getattr("RFC822Name")?
            .call_method1("_init_without_validation", (data.0,))?
            .to_object(py),
        GeneralName::DNSName(data) => x509_module
            .getattr("DNSName")?
            .call_method1("_init_without_validation", (data.0,))?
            .to_object(py),
        GeneralName::DirectoryName(data) => {
            let py_name = parse_name(py, &data)?;
            x509_module
                .call_method1("DirectoryName", (py_name,))?
                .to_object(py)
        }
        GeneralName::UniformResourceIdentifier(data) => x509_module
            .getattr("UniformResourceIdentifier")?
            .call_method1("_init_without_validation", (data.0,))?
            .to_object(py),
        GeneralName::IPAddress(data) => {
            let ip_module = py.import("ipaddress")?;
            if data.len() == 4 || data.len() == 16 {
                let addr = ip_module.call_method1("ip_address", (data,))?.to_object(py);
                x509_module
                    .call_method1("IPAddress", (addr,))?
                    .to_object(py)
            } else {
                // if it's not an IPv4 or IPv6 we assume it's an IPNetwork and
                // verify length in this function.
                create_ip_network(py, data)?
            }
        }
        GeneralName::RegisteredID(data) => {
            let oid = x509_module
                .call_method1("ObjectIdentifier", (data.to_string(),))?
                .to_object(py);
            x509_module
                .call_method1("RegisteredID", (oid,))?
                .to_object(py)
        }
        _ => {
            return Err(PyAsn1Error::from(pyo3::PyErr::from_instance(
                x509_module.call_method1(
                    "UnsupportedGeneralNameType",
                    ("x400Address/EDIPartyName are not supported types",),
                )?,
            )))
        }
    };
    Ok(py_gn)
}

pub(crate) fn parse_general_names<'a>(
    py: pyo3::Python<'_>,
    gn_seq: &asn1::SequenceOf<'a, GeneralName<'a>>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let gns = pyo3::types::PyList::empty(py);
    for gn in gn_seq.clone() {
        let py_gn = parse_general_name(py, gn)?;
        gns.append(py_gn)?;
    }
    Ok(gns.to_object(py))
}

fn create_ip_network(py: pyo3::Python<'_>, data: &[u8]) -> Result<pyo3::PyObject, PyAsn1Error> {
    let ip_module = py.import("ipaddress")?;
    let x509_module = py.import("cryptography.x509")?;
    let prefix = match data.len() {
        8 => {
            let num = u32::from_be_bytes(data[4..].try_into().unwrap());
            ipv4_netmask(num)
        }
        32 => {
            let num = u128::from_be_bytes(data[16..].try_into().unwrap());
            ipv6_netmask(num)
        }
        _ => Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            format!("Invalid IPNetwork, must be 8 bytes for IPv4 and 32 bytes for IPv6. Found length: {}", data.len()),
        ))),
    };
    let base = ip_module.call_method1(
        "ip_address",
        (pyo3::types::PyBytes::new(py, &data[..data.len() / 2]),),
    )?;
    let net = format!(
        "{}/{}",
        base.getattr("exploded")?.extract::<&str>()?,
        prefix?
    );
    let addr = ip_module.call_method1("ip_network", (net,))?.to_object(py);
    Ok(x509_module
        .call_method1("IPAddress", (addr,))?
        .to_object(py))
}

fn ipv4_netmask(num: u32) -> Result<u32, PyAsn1Error> {
    // we invert and check leading zeros because leading_ones wasn't stabilized
    // until 1.46.0. When we raise our MSRV we should change this
    if (!num).leading_zeros() + num.trailing_zeros() != 32 {
        return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            "Invalid netmask",
        )));
    }
    Ok((!num).leading_zeros())
}

fn ipv6_netmask(num: u128) -> Result<u32, PyAsn1Error> {
    // we invert and check leading zeros because leading_ones wasn't stabilized
    // until 1.46.0. When we raise our MSRV we should change this
    if (!num).leading_zeros() + num.trailing_zeros() != 128 {
        return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            "Invalid netmask",
        )));
    }
    Ok((!num).leading_zeros())
}

pub(crate) fn parse_and_cache_extensions<
    'p,
    F: Fn(&asn1::ObjectIdentifier<'_>, &[u8]) -> Result<Option<&'p pyo3::PyAny>, PyAsn1Error>,
>(
    py: pyo3::Python<'p>,
    cached_extensions: &mut Option<pyo3::PyObject>,
    raw_exts: &Option<Extensions<'_>>,
    parse_ext: F,
) -> pyo3::PyResult<pyo3::PyObject> {
    if let Some(cached) = cached_extensions {
        return Ok(cached.clone_ref(py));
    }

    let x509_module = py.import("cryptography.x509")?;
    let exts = pyo3::types::PyList::empty(py);
    let mut seen_oids = HashSet::new();
    if let Some(raw_exts) = raw_exts {
        for raw_ext in raw_exts.unwrap_read().clone() {
            let oid_obj =
                x509_module.call_method1("ObjectIdentifier", (raw_ext.extn_id.to_string(),))?;

            if seen_oids.contains(&raw_ext.extn_id) {
                return Err(pyo3::PyErr::from_instance(x509_module.call_method1(
                    "DuplicateExtension",
                    (
                        format!("Duplicate {} extension found", raw_ext.extn_id),
                        oid_obj,
                    ),
                )?));
            }

            let extn_value = match parse_ext(&raw_ext.extn_id, raw_ext.extn_value)? {
                Some(e) => e,
                None => x509_module
                    .call_method1("UnrecognizedExtension", (oid_obj, raw_ext.extn_value))?,
            };
            let ext_obj =
                x509_module.call_method1("Extension", (oid_obj, raw_ext.critical, extn_value))?;
            exts.append(ext_obj)?;
            seen_oids.insert(raw_ext.extn_id);
        }
    }
    let extensions = x509_module
        .call_method1("Extensions", (exts,))?
        .to_object(py);
    *cached_extensions = Some(extensions.clone_ref(py));
    Ok(extensions)
}

pub(crate) fn encode_extensions<
    'p,
    F: Fn(&asn1::ObjectIdentifier<'_>, &pyo3::PyAny) -> pyo3::PyResult<Option<Vec<u8>>>,
>(
    py: pyo3::Python<'p>,
    py_exts: &'p pyo3::PyAny,
    encode_ext: F,
) -> pyo3::PyResult<Option<Extensions<'p>>> {
    let unrecognized_extension_type: &pyo3::types::PyType = py
        .import("cryptography.x509")?
        .getattr("UnrecognizedExtension")?
        .extract()?;

    let mut exts = vec![];
    for py_ext in py_exts.iter()? {
        let py_ext = py_ext?;
        let oid = asn1::ObjectIdentifier::from_string(
            py_ext
                .getattr("oid")?
                .getattr("dotted_string")?
                .extract::<&str>()?,
        )
        .unwrap();

        let ext_val = py_ext.getattr("value")?;
        if unrecognized_extension_type.is_instance(ext_val)? {
            exts.push(Extension {
                extn_id: oid,
                critical: py_ext.getattr("critical")?.extract()?,
                extn_value: ext_val.getattr("value")?.extract::<&[u8]>()?,
            });
            continue;
        }
        match encode_ext(&oid, ext_val)? {
            Some(data) => {
                // TODO: extra copy
                let py_data = pyo3::types::PyBytes::new(py, &data);
                exts.push(Extension {
                    extn_id: oid,
                    critical: py_ext.getattr("critical")?.extract()?,
                    extn_value: py_data.as_bytes(),
                })
            }
            None => {
                return Err(pyo3::exceptions::PyNotImplementedError::new_err(format!(
                    "Extension not supported: {}",
                    oid
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

#[pyo3::prelude::pyfunction]
fn encode_extension_value<'p>(
    py: pyo3::Python<'p>,
    py_ext: &'p pyo3::PyAny,
) -> pyo3::PyResult<&'p pyo3::types::PyBytes> {
    let oid = asn1::ObjectIdentifier::from_string(
        py_ext
            .getattr("oid")?
            .getattr("dotted_string")?
            .extract::<&str>()?,
    )
    .unwrap();

    if let Some(data) = x509::extensions::encode_extension(&oid, py_ext)? {
        // TODO: extra copy
        let py_data = pyo3::types::PyBytes::new(py, &data);
        return Ok(py_data);
    }

    return Err(pyo3::exceptions::PyNotImplementedError::new_err(format!(
        "Extension not supported: {}",
        oid
    )));
}

pub(crate) fn chrono_to_py<'p>(
    py: pyo3::Python<'p>,
    dt: &chrono::DateTime<chrono::Utc>,
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    let datetime_module = py.import("datetime")?;
    datetime_module.getattr("datetime")?.call1((
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
    ))
}

pub(crate) fn py_to_chrono(val: &pyo3::PyAny) -> pyo3::PyResult<chrono::DateTime<chrono::Utc>> {
    Ok(chrono::Utc
        .ymd(
            val.getattr("year")?.extract()?,
            val.getattr("month")?.extract()?,
            val.getattr("day")?.extract()?,
        )
        .and_hms(
            val.getattr("hour")?.extract()?,
            val.getattr("minute")?.extract()?,
            val.getattr("second")?.extract()?,
        ))
}

#[derive(Hash, PartialEq, Clone)]
pub(crate) enum Asn1ReadableOrWritable<'a, T, U> {
    Read(T, PhantomData<&'a ()>),
    Write(U, PhantomData<&'a ()>),
}

impl<'a, T, U> Asn1ReadableOrWritable<'a, T, U> {
    pub(crate) fn new_read(v: T) -> Self {
        Asn1ReadableOrWritable::Read(v, PhantomData)
    }

    pub(crate) fn new_write(v: U) -> Self {
        Asn1ReadableOrWritable::Write(v, PhantomData)
    }

    pub(crate) fn unwrap_read(&self) -> &T {
        match self {
            Asn1ReadableOrWritable::Read(v, _) => v,
            Asn1ReadableOrWritable::Write(_, _) => panic!("unwrap_read called on a Write value"),
        }
    }
}

impl<'a, T: asn1::SimpleAsn1Readable<'a>, U> asn1::SimpleAsn1Readable<'a>
    for Asn1ReadableOrWritable<'a, T, U>
{
    const TAG: u8 = T::TAG;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        Ok(Self::new_read(T::parse_data(data)?))
    }
}

impl<'a, T: asn1::SimpleAsn1Writable<'a>, U: asn1::SimpleAsn1Writable<'a>>
    asn1::SimpleAsn1Writable<'a> for Asn1ReadableOrWritable<'a, T, U>
{
    const TAG: u8 = U::TAG;
    fn write_data(&self, w: &mut Vec<u8>) {
        match self {
            Asn1ReadableOrWritable::Read(v, _) => T::write_data(v, w),
            Asn1ReadableOrWritable::Write(v, _) => U::write_data(v, w),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Asn1ReadableOrWritable, RawTlv};
    use asn1::Asn1Readable;

    #[test]
    #[should_panic]
    fn test_asn1_readable_or_writable_unwrap_read() {
        Asn1ReadableOrWritable::<u32, u32>::new_write(17).unwrap_read();
    }

    #[test]
    fn test_asn1_readable_or_writable_write_read_data() {
        let v = Asn1ReadableOrWritable::<u32, u32>::new_read(17);
        assert_eq!(&asn1::write_single(&v), b"\x02\x01\x11");
    }

    #[test]
    fn test_raw_tlv_can_parse() {
        assert!(RawTlv::can_parse(123));
    }
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_wrapped(pyo3::wrap_pyfunction!(encode_extension_value))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(encode_name_bytes))?;

    Ok(())
}
