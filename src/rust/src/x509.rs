// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{big_asn1_uint_to_py, AttributeTypeValue, Name, PyAsn1Error};
use chrono::{Datelike, Timelike};
use pyo3::conversion::ToPyObject;
use pyo3::types::IntoPyDict;
use std::collections::hash_map::DefaultHasher;
use std::convert::TryInto;
use std::hash::{Hash, Hasher};

lazy_static::lazy_static! {
    static ref TLS_FEATURE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.24").unwrap();
    static ref PRECERT_POISON_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.11129.2.4.3").unwrap();
    static ref OCSP_NO_CHECK_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.5").unwrap();
    static ref AUTHORITY_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.1").unwrap();
    static ref SUBJECT_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.11").unwrap();

    static ref KEY_USAGE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.15").unwrap();
    static ref POLICY_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.36").unwrap();
    static ref AUTHORITY_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.35").unwrap();
    static ref EXTENDED_KEY_USAGE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.37").unwrap();
    static ref BASIC_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.19").unwrap();
    static ref SUBJECT_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.14").unwrap();
    static ref INHIBIT_ANY_POLICY_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.54").unwrap();
    static ref CRL_REASON_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.21").unwrap();
    static ref ISSUING_DISTRIBUTION_POINT_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.28").unwrap();
    static ref CERTIFICATE_ISSUER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.29").unwrap();
    static ref NAME_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.30").unwrap();
    static ref CRL_DISTRIBUTION_POINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.31").unwrap();
    static ref FRESHEST_CRL_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.46").unwrap();
    static ref CRL_NUMBER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.20").unwrap();
    static ref INVALIDITY_DATE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.24").unwrap();
    static ref DELTA_CRL_INDICATOR_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.27").unwrap();
    static ref SUBJECT_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.17").unwrap();
    static ref ISSUER_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.18").unwrap();
    static ref PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.11129.2.4.2").unwrap();
}

struct UnvalidatedIA5String<'a>(&'a str);

impl<'a> asn1::SimpleAsn1Readable<'a> for UnvalidatedIA5String<'a> {
    const TAG: u8 = 0x16;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        Ok(UnvalidatedIA5String(
            std::str::from_utf8(data).map_err(|_| asn1::ParseError::InvalidValue)?,
        ))
    }
}

#[derive(asn1::Asn1Read)]
struct NameConstraints<'a> {
    #[implicit(0)]
    permitted_subtrees: Option<asn1::SequenceOf<'a, GeneralSubtree<'a>>>,

    #[implicit(1)]
    excluded_subtrees: Option<asn1::SequenceOf<'a, GeneralSubtree<'a>>>,
}

#[derive(asn1::Asn1Read)]
struct GeneralSubtree<'a> {
    base: GeneralName<'a>,

    #[implicit(0)]
    #[default(0)]
    // TODO: doesn't like u64
    _minimum: i64,

    #[implicit(1)]
    _maximum: Option<u64>,
}

fn parse_general_subtrees<'a>(
    py: pyo3::Python<'_>,
    subtrees: asn1::SequenceOf<'a, GeneralSubtree<'a>>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let gns = pyo3::types::PyList::empty(py);
    for gs in subtrees {
        gns.append(parse_general_name(py, gs.base)?)?;
    }
    Ok(gns.to_object(py))
}

#[derive(asn1::Asn1Read)]
struct IssuingDistributionPoint<'a> {
    #[explicit(0)]
    distribution_point: Option<DistributionPointName<'a>>,

    #[implicit(1)]
    #[default(false)]
    only_contains_user_certs: bool,

    #[implicit(2)]
    #[default(false)]
    only_contains_ca_certs: bool,

    #[implicit(3)]
    only_some_reasons: Option<asn1::BitString<'a>>,

    #[implicit(4)]
    #[default(false)]
    indirect_crl: bool,

    #[implicit(5)]
    #[default(false)]
    only_contains_attribute_certs: bool,
}

#[derive(asn1::Asn1Read)]
struct DistributionPoint<'a> {
    #[explicit(0)]
    distribution_point: Option<DistributionPointName<'a>>,

    #[implicit(1)]
    reasons: Option<asn1::BitString<'a>>,

    #[implicit(2)]
    crl_issuer: Option<asn1::SequenceOf<'a, GeneralName<'a>>>,
}

#[derive(asn1::Asn1Read)]
enum DistributionPointName<'a> {
    #[implicit(0)]
    FullName(asn1::SequenceOf<'a, GeneralName<'a>>),

    #[implicit(1)]
    NameRelativeToCRLIssuer(asn1::SetOf<'a, AttributeTypeValue<'a>>),
}

#[derive(asn1::Asn1Read)]
struct AuthorityKeyIdentifier<'a> {
    #[implicit(0)]
    key_identifier: Option<&'a [u8]>,
    #[implicit(1)]
    authority_cert_issuer: Option<asn1::SequenceOf<'a, GeneralName<'a>>>,
    #[implicit(2)]
    authority_cert_serial_number: Option<asn1::BigUint<'a>>,
}

fn parse_distribution_point_name(
    py: pyo3::Python<'_>,
    dp: DistributionPointName<'_>,
) -> Result<(pyo3::PyObject, pyo3::PyObject), PyAsn1Error> {
    Ok(match dp {
        DistributionPointName::FullName(data) => (parse_general_names(py, data)?, py.None()),
        DistributionPointName::NameRelativeToCRLIssuer(data) => (py.None(), parse_rdn(py, data)?),
    })
}

fn parse_distribution_point(
    py: pyo3::Python<'_>,
    dp: DistributionPoint<'_>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let (full_name, relative_name) = match dp.distribution_point {
        Some(data) => parse_distribution_point_name(py, data)?,
        None => (py.None(), py.None()),
    };
    let reasons = parse_distribution_point_reasons(py, dp.reasons)?;
    let crl_issuer = match dp.crl_issuer {
        Some(aci) => parse_general_names(py, aci)?,
        None => py.None(),
    };
    let x509_module = py.import("cryptography.x509")?;
    Ok(x509_module
        .call1(
            "DistributionPoint",
            (full_name, relative_name, reasons, crl_issuer),
        )?
        .to_object(py))
}

fn parse_distribution_points(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let dps = asn1::parse_single::<asn1::SequenceOf<'_, DistributionPoint<'_>>>(data)?;
    let py_dps = pyo3::types::PyList::empty(py);
    for dp in dps {
        let py_dp = parse_distribution_point(py, dp)?;
        py_dps.append(py_dp)?;
    }
    Ok(py_dps.to_object(py))
}

fn parse_distribution_point_reasons(
    py: pyo3::Python<'_>,
    reasons: Option<asn1::BitString<'_>>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let reason_bit_mapping = py
        .import("cryptography.x509.extensions")?
        .getattr("_REASON_BIT_MAPPING")?;
    Ok(match reasons {
        Some(bs) => {
            let mut vec = Vec::new();
            for i in 1..=8 {
                if bs.has_bit_set(i) {
                    vec.push(reason_bit_mapping.get_item(i)?);
                }
            }
            pyo3::types::PyFrozenSet::new(py, &vec)?.to_object(py)
        }
        None => py.None(),
    })
}

#[derive(asn1::Asn1Read)]
enum GeneralName<'a> {
    #[implicit(0)]
    OtherName(AttributeTypeValue<'a>),

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

#[derive(asn1::Asn1Read)]
struct BasicConstraints {
    #[default(false)]
    ca: bool,
    path_length: Option<u64>,
}

#[derive(asn1::Asn1Read)]
struct PolicyConstraints {
    #[implicit(0)]
    require_explicit_policy: Option<u64>,
    #[implicit(1)]
    inhibit_policy_mapping: Option<u64>,
}

#[derive(asn1::Asn1Read)]
struct AccessDescription<'a> {
    access_method: asn1::ObjectIdentifier<'a>,
    access_location: GeneralName<'a>,
}

fn parse_authority_key_identifier(
    py: pyo3::Python<'_>,
    ext_data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let aki = asn1::parse_single::<AuthorityKeyIdentifier<'_>>(ext_data)?;
    let serial = match aki.authority_cert_serial_number {
        Some(biguint) => big_asn1_uint_to_py(py, biguint)?.to_object(py),
        None => py.None(),
    };
    let issuer = match aki.authority_cert_issuer {
        Some(aci) => parse_general_names(py, aci)?,
        None => py.None(),
    };
    Ok(x509_module
        .call1(
            "AuthorityKeyIdentifier",
            (aki.key_identifier, issuer, serial),
        )?
        .to_object(py))
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
    let py_data =
        std::str::from_utf8(attribute.value.data()).map_err(|_| asn1::ParseError::InvalidValue)?;
    Ok(x509_module
        .call_method1("NameAttribute", (oid, py_data, py_tag))?
        .to_object(py))
}

fn parse_rdn<'a>(
    py: pyo3::Python<'_>,
    rdn: asn1::SetOf<'a, AttributeTypeValue<'a>>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let py_attrs = pyo3::types::PySet::empty(py)?;
    for attribute in rdn {
        let na = parse_name_attribute(py, attribute)?;
        py_attrs.add(na)?;
    }
    Ok(x509_module
        .call_method1("RelativeDistinguishedName", (py_attrs,))?
        .to_object(py))
}

fn parse_name(py: pyo3::Python<'_>, name: Name<'_>) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let py_rdns = pyo3::types::PyList::empty(py);
    for rdn in name {
        let py_rdn = parse_rdn(py, rdn)?;
        py_rdns.append(py_rdn)?;
    }
    let py_name = x509_module.call_method1("Name", (py_rdns,))?.to_object(py);
    Ok(py_name)
}

fn ipv4_netmask(data: &[u8]) -> Result<u32, PyAsn1Error> {
    let num = u32::from_be_bytes(data[4..].try_into().unwrap());
    if num.leading_ones() + num.trailing_zeros() != 32 {
        return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            "Invalid netmask"
        )));
    }
    return Ok(num.leading_ones())
}

fn ipv6_netmask(data: &[u8]) -> Result<u32, PyAsn1Error> {
    let num = u128::from_be_bytes(data[16..].try_into().unwrap());
    if num.leading_ones() + num.trailing_zeros() != 128 {
        return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            "Invalid netmask"
        )));
    }
    return Ok(num.leading_ones())
}

fn create_ip_network(py: pyo3::Python<'_>, data: &[u8]) -> Result<pyo3::PyObject, PyAsn1Error> {
    let ip_module = py.import("ipaddress")?;
    let x509_module = py.import("cryptography.x509")?;
    let prefix = match data.len() {
        8 => ipv4_netmask(data)?,
        32 => ipv6_netmask(data)?,
        _ => Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            "Invalid IPNetwork, must be 8 bytes for IPv4 and 32 bytes for IPv6"
        )))?
    };
    let base = ip_module.call_method1("ip_address", (pyo3::types::PyBytes::new(py, &data[..data.len() / 2]),))?;
    let net = format!("{}/{}", base.getattr("exploded")?.extract::<&str>()?, prefix);
    Ok(x509_module
        .call_method1(
            "IPAddress",
            (ip_module.call_method1("ip_network", (net,))?.to_object(py),),
        )?
        .to_object(py))
}

fn parse_general_name(
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
                .call_method1("OtherName", (oid, data.value.data()))?
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
            let py_name = parse_name(py, data)?;
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
            if data.len() == 4 && data.len() == 16 {
                x509_module
                    .call_method1(
                        "IPAddress",
                        (ip_module.call_method1("ip_address", (data,))?.to_object(py),),
                    )?
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

fn parse_general_names<'a>(
    py: pyo3::Python<'_>,
    gn_seq: asn1::SequenceOf<'a, GeneralName<'a>>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let gns = pyo3::types::PyList::empty(py);
    for gn in gn_seq {
        let py_gn = parse_general_name(py, gn)?;
        gns.append(py_gn)?;
    }
    Ok(gns.to_object(py))
}

fn parse_access_descriptions(
    py: pyo3::Python<'_>,
    ext_data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let ads = pyo3::types::PyList::empty(py);
    for access in asn1::parse_single::<asn1::SequenceOf<'_, AccessDescription<'_>>>(ext_data)? {
        let py_oid = x509_module
            .call_method1("ObjectIdentifier", (access.access_method.to_string(),))?
            .to_object(py);
        let gn = parse_general_name(py, access.access_location)?;
        let ad = x509_module
            .call1("AccessDescription", (py_oid, gn))?
            .to_object(py);
        ads.append(ad)?;
    }
    Ok(ads.to_object(py))
}

struct TLSReader<'a> {
    data: &'a [u8],
}

impl<'a> TLSReader<'a> {
    fn new(data: &'a [u8]) -> TLSReader<'a> {
        TLSReader { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn read_byte(&mut self) -> Result<u8, PyAsn1Error> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PyAsn1Error> {
        if length > self.data.len() {
            return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                "Invalid SCT length",
            )));
        }
        let (result, data) = self.data.split_at(length);
        self.data = data;
        Ok(result)
    }

    fn read_length_prefixed(&mut self) -> Result<TLSReader<'a>, PyAsn1Error> {
        let length = u16::from_be_bytes(self.read_exact(2)?.try_into().unwrap());
        Ok(TLSReader::new(self.read_exact(length.into())?))
    }
}

#[derive(Clone)]
pub(crate) enum LogEntryType {
    Certificate,
    PreCertificate,
}

#[pyo3::prelude::pyclass]
struct Sct {
    log_id: [u8; 32],
    timestamp: u64,
    entry_type: LogEntryType,
    sct_data: Vec<u8>,
}

#[pyo3::prelude::pymethods]
impl Sct {
    #[getter]
    fn version<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        py.import("cryptography.x509.certificate_transparency")?
            .getattr("Version")?
            .getattr("v1")
    }

    #[getter]
    fn log_id(&self) -> &[u8] {
        &self.log_id
    }

    #[getter]
    fn timestamp<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let datetime_class = py.import("datetime")?.getattr("datetime")?;
        datetime_class
            .call_method1("utcfromtimestamp", (self.timestamp / 1000,))?
            .call_method(
                "replace",
                (),
                Some(vec![("microsecond", self.timestamp % 1000 * 1000)].into_py_dict(py)),
            )
    }

    #[getter]
    fn entry_type<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let et_class = py
            .import("cryptography.x509.certificate_transparency")?
            .getattr("LogEntryType")?;
        let attr_name = match self.entry_type {
            LogEntryType::Certificate => "X509_CERTIFICATE",
            LogEntryType::PreCertificate => "PRE_CERTIFICATE",
        };
        et_class.getattr(attr_name)
    }
}

#[pyo3::prelude::pyproto]
impl pyo3::class::basic::PyObjectProtocol for Sct {
    fn __richcmp__(
        &self,
        other: pyo3::pycell::PyRef<Sct>,
        op: pyo3::class::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::class::basic::CompareOp::Eq => Ok(self.sct_data == other.sct_data),
            pyo3::class::basic::CompareOp::Ne => Ok(self.sct_data != other.sct_data),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "SCTs cannot be ordered",
            )),
        }
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.sct_data.hash(&mut hasher);
        hasher.finish()
    }
}

#[pyo3::prelude::pyfunction]
fn encode_precertificate_signed_certificate_timestamps(
    py: pyo3::Python<'_>,
    extension: &pyo3::PyAny,
) -> pyo3::PyResult<pyo3::PyObject> {
    let mut length = 0;
    for sct in extension.iter()? {
        let sct = sct?.downcast::<pyo3::pycell::PyCell<Sct>>()?;
        length += sct.borrow().sct_data.len() + 2;
    }

    let mut result = vec![];
    result.extend_from_slice(&(length as u16).to_be_bytes());
    for sct in extension.iter()? {
        let sct = sct?.downcast::<pyo3::pycell::PyCell<Sct>>()?;
        result.extend_from_slice(&(sct.borrow().sct_data.len() as u16).to_be_bytes());
        result.extend_from_slice(&sct.borrow().sct_data);
    }
    Ok(pyo3::types::PyBytes::new(py, &asn1::write_single(&result.as_slice())).to_object(py))
}

pub(crate) fn parse_scts(
    py: pyo3::Python<'_>,
    data: &[u8],
    entry_type: LogEntryType,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let mut reader = TLSReader::new(data).read_length_prefixed()?;

    let py_scts = pyo3::types::PyList::empty(py);
    while !reader.is_empty() {
        let mut sct_data = reader.read_length_prefixed()?;
        let raw_sct_data = sct_data.data.to_vec();
        let version = sct_data.read_byte()?;
        if version != 0 {
            return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                "Invalid SCT version",
            )));
        }
        let log_id = sct_data.read_exact(32)?.try_into().unwrap();
        let timestamp = u64::from_be_bytes(sct_data.read_exact(8)?.try_into().unwrap());
        let _extensions = sct_data.read_length_prefixed()?;
        let _sig_alg = sct_data.read_exact(2)?;
        let _signature = sct_data.read_length_prefixed()?;

        let sct = Sct {
            log_id,
            timestamp,
            entry_type: entry_type.clone(),
            sct_data: raw_sct_data,
        };
        py_scts.append(pyo3::PyCell::new(py, sct)?)?;
    }
    Ok(py_scts.to_object(py))
}

#[pyo3::prelude::pyfunction]
fn parse_x509_extension(
    py: pyo3::Python<'_>,
    der_oid: &[u8],
    ext_data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let oid = asn1::ObjectIdentifier::from_der(der_oid).unwrap();

    let x509_module = py.import("cryptography.x509")?;
    if oid == *SUBJECT_ALTERNATIVE_NAME_OID {
        let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, GeneralName<'_>>>(ext_data)?;
        let sans = parse_general_names(py, gn_seq)?;
        Ok(x509_module
            .call1("SubjectAlternativeName", (sans,))?
            .to_object(py))
    } else if oid == *ISSUER_ALTERNATIVE_NAME_OID {
        let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, GeneralName<'_>>>(ext_data)?;
        let ians = parse_general_names(py, gn_seq)?;
        Ok(x509_module
            .call1("IssuerAlternativeName", (ians,))?
            .to_object(py))
    } else if oid == *TLS_FEATURE_OID {
        let tls_feature_type_to_enum = py
            .import("cryptography.x509.extensions")?
            .getattr("_TLS_FEATURE_TYPE_TO_ENUM")?;

        let features = pyo3::types::PyList::empty(py);
        for feature in asn1::parse_single::<asn1::SequenceOf<'_, u64>>(ext_data)? {
            let py_feature = tls_feature_type_to_enum.get_item(feature.to_object(py))?;
            features.append(py_feature)?;
        }
        Ok(x509_module.call1("TLSFeature", (features,))?.to_object(py))
    } else if oid == *SUBJECT_KEY_IDENTIFIER_OID {
        let identifier = asn1::parse_single::<&[u8]>(ext_data)?;
        Ok(x509_module
            .call1("SubjectKeyIdentifier", (identifier,))?
            .to_object(py))
    } else if oid == *EXTENDED_KEY_USAGE_OID {
        let ekus = pyo3::types::PyList::empty(py);
        for oid in asn1::parse_single::<asn1::SequenceOf<'_, asn1::ObjectIdentifier<'_>>>(ext_data)?
        {
            let oid_obj = x509_module.call_method1("ObjectIdentifier", (oid.to_string(),))?;
            ekus.append(oid_obj)?;
        }
        Ok(x509_module
            .call1("ExtendedKeyUsage", (ekus,))?
            .to_object(py))
    } else if oid == *KEY_USAGE_OID {
        let kus = asn1::parse_single::<asn1::BitString<'_>>(ext_data)?;
        let digital_signature = kus.has_bit_set(0);
        let content_comitment = kus.has_bit_set(1);
        let key_encipherment = kus.has_bit_set(2);
        let data_encipherment = kus.has_bit_set(3);
        let key_agreement = kus.has_bit_set(4);
        let key_cert_sign = kus.has_bit_set(5);
        let crl_sign = kus.has_bit_set(6);
        let encipher_only = kus.has_bit_set(7);
        let decipher_only = kus.has_bit_set(8);
        Ok(x509_module
            .call1(
                "KeyUsage",
                (
                    digital_signature,
                    content_comitment,
                    key_encipherment,
                    data_encipherment,
                    key_agreement,
                    key_cert_sign,
                    crl_sign,
                    encipher_only,
                    decipher_only,
                ),
            )?
            .to_object(py))
    } else if oid == *AUTHORITY_INFORMATION_ACCESS_OID {
        let ads = parse_access_descriptions(py, ext_data)?;
        Ok(x509_module
            .call1("AuthorityInformationAccess", (ads,))?
            .to_object(py))
    } else if oid == *SUBJECT_INFORMATION_ACCESS_OID {
        let ads = parse_access_descriptions(py, ext_data)?;
        Ok(x509_module
            .call1("SubjectInformationAccess", (ads,))?
            .to_object(py))
    } else if oid == *POLICY_CONSTRAINTS_OID {
        let pc = asn1::parse_single::<PolicyConstraints>(ext_data)?;
        Ok(x509_module
            .call1(
                "PolicyConstraints",
                (pc.require_explicit_policy, pc.inhibit_policy_mapping),
            )?
            .to_object(py))
    } else if oid == *PRECERT_POISON_OID {
        asn1::parse_single::<()>(ext_data)?;
        Ok(x509_module.call0("PrecertPoison")?.to_object(py))
    } else if oid == *OCSP_NO_CHECK_OID {
        asn1::parse_single::<()>(ext_data)?;
        Ok(x509_module.call0("OCSPNoCheck")?.to_object(py))
    } else if oid == *INHIBIT_ANY_POLICY_OID {
        let bignum = asn1::parse_single::<asn1::BigUint<'_>>(ext_data)?;
        let pynum = big_asn1_uint_to_py(py, bignum)?;
        Ok(x509_module
            .call1("InhibitAnyPolicy", (pynum,))?
            .to_object(py))
    } else if oid == *BASIC_CONSTRAINTS_OID {
        let bc = asn1::parse_single::<BasicConstraints>(ext_data)?;
        Ok(x509_module
            .call1("BasicConstraints", (bc.ca, bc.path_length))?
            .to_object(py))
    } else if oid == *AUTHORITY_KEY_IDENTIFIER_OID {
        Ok(parse_authority_key_identifier(py, ext_data)?)
    } else if oid == *CRL_DISTRIBUTION_POINTS_OID {
        let dp = parse_distribution_points(py, ext_data)?;
        Ok(x509_module
            .call1("CRLDistributionPoints", (dp,))?
            .to_object(py))
    } else if oid == *FRESHEST_CRL_OID {
        Ok(x509_module
            .call1("FreshestCRL", (parse_distribution_points(py, ext_data)?,))?
            .to_object(py))
    } else if oid == *PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID {
        let contents = asn1::parse_single::<&[u8]>(ext_data)?;
        let scts = parse_scts(py, contents, LogEntryType::PreCertificate)?;
        Ok(x509_module
            .call1("PrecertificateSignedCertificateTimestamps", (scts,))?
            .to_object(py))
    } else if oid == *NAME_CONSTRAINTS_OID {
        let nc = asn1::parse_single::<NameConstraints<'_>>(ext_data)?;
        let permitted_subtrees = match nc.permitted_subtrees {
            Some(data) => parse_general_subtrees(py, data)?,
            None => py.None(),
        };
        let excluded_subtrees = match nc.excluded_subtrees {
            Some(data) => parse_general_subtrees(py, data)?,
            None => py.None(),
        };
        Ok(x509_module
            .call1("NameConstraints", (permitted_subtrees, excluded_subtrees))?
            .to_object(py))
    } else {
        Ok(py.None())
    }
}

#[pyo3::prelude::pyfunction]
pub(crate) fn parse_crl_entry_extension(
    py: pyo3::Python<'_>,
    der_oid: &[u8],
    ext_data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let oid = asn1::ObjectIdentifier::from_der(der_oid).unwrap();

    let x509_module = py.import("cryptography.x509")?;
    if oid == *CRL_REASON_OID {
        let flag_name = match asn1::parse_single::<asn1::Enumerated>(ext_data)?.value() {
            0 => "unspecified",
            1 => "key_compromise",
            2 => "ca_compromise",
            3 => "affiliation_changed",
            4 => "superseded",
            5 => "cessation_of_operation",
            6 => "certificate_hold",
            8 => "remove_from_crl",
            9 => "privilege_withdrawn",
            10 => "aa_compromise",
            value => {
                return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                    format!("Unsupported reason code: {}", value),
                )))
            }
        };
        let flag = x509_module.getattr("ReasonFlags")?.getattr(flag_name)?;
        Ok(x509_module.call1("CRLReason", (flag,))?.to_object(py))
    } else if oid == *CERTIFICATE_ISSUER_OID {
        let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, GeneralName<'_>>>(ext_data)?;
        let gns = parse_general_names(py, gn_seq)?;
        Ok(x509_module
            .call1("CertificateIssuer", (gns,))?
            .to_object(py))
    } else if oid == *INVALIDITY_DATE_OID {
        let time = asn1::parse_single::<asn1::GeneralizedTime>(ext_data)?;
        let time_chrono = time.as_chrono();
        let datetime_module = py.import("datetime")?;
        let py_dt = datetime_module.call1(
            "datetime",
            (
                time_chrono.year(),
                time_chrono.month(),
                time_chrono.day(),
                time_chrono.hour(),
                time_chrono.minute(),
                time_chrono.second(),
            ),
        )?;
        Ok(x509_module.call1("InvalidityDate", (py_dt,))?.to_object(py))
    } else {
        Ok(py.None())
    }
}

#[pyo3::prelude::pyfunction]
fn parse_crl_extension(
    py: pyo3::Python<'_>,
    der_oid: &[u8],
    ext_data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let oid = asn1::ObjectIdentifier::from_der(der_oid).unwrap();

    let x509_module = py.import("cryptography.x509")?;
    if oid == *CRL_NUMBER_OID {
        let bignum = asn1::parse_single::<asn1::BigUint<'_>>(ext_data)?;
        let pynum = big_asn1_uint_to_py(py, bignum)?;
        Ok(x509_module.call1("CRLNumber", (pynum,))?.to_object(py))
    } else if oid == *DELTA_CRL_INDICATOR_OID {
        let bignum = asn1::parse_single::<asn1::BigUint<'_>>(ext_data)?;
        let pynum = big_asn1_uint_to_py(py, bignum)?;
        Ok(x509_module
            .call1("DeltaCRLIndicator", (pynum,))?
            .to_object(py))
    } else if oid == *ISSUER_ALTERNATIVE_NAME_OID {
        let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, GeneralName<'_>>>(ext_data)?;
        let ians = parse_general_names(py, gn_seq)?;
        Ok(x509_module
            .call1("IssuerAlternativeName", (ians,))?
            .to_object(py))
    } else if oid == *AUTHORITY_INFORMATION_ACCESS_OID {
        let ads = parse_access_descriptions(py, ext_data)?;
        Ok(x509_module
            .call1("AuthorityInformationAccess", (ads,))?
            .to_object(py))
    } else if oid == *AUTHORITY_KEY_IDENTIFIER_OID {
        Ok(parse_authority_key_identifier(py, ext_data)?)
    } else if oid == *ISSUING_DISTRIBUTION_POINT_OID {
        let idp = asn1::parse_single::<IssuingDistributionPoint<'_>>(ext_data)?;
        let (full_name, relative_name) = match idp.distribution_point {
            Some(data) => parse_distribution_point_name(py, data)?,
            None => (py.None(), py.None()),
        };
        let reasons = parse_distribution_point_reasons(py, idp.only_some_reasons)?;
        Ok(x509_module
            .call1(
                "IssuingDistributionPoint",
                (
                    full_name,
                    relative_name,
                    idp.only_contains_user_certs,
                    idp.only_contains_ca_certs,
                    reasons,
                    idp.indirect_crl,
                    idp.only_contains_attribute_certs,
                ),
            )?
            .to_object(py))
    } else if oid == *FRESHEST_CRL_OID {
        Ok(x509_module
            .call1("FreshestCRL", (parse_distribution_points(py, ext_data)?,))?
            .to_object(py))
    } else {
        Ok(py.None())
    }
}

pub(crate) fn create_submodule(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "x509")?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_x509_extension))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_crl_entry_extension))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_crl_extension))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(
        encode_precertificate_signed_certificate_timestamps
    ))?;
    submod.add_class::<Sct>()?;

    Ok(submod)
}
