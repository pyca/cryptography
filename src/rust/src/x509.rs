// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{big_asn1_uint_to_py, AttributeTypeValue, Name, PyAsn1Error};
use pyo3::conversion::ToPyObject;

lazy_static::lazy_static! {
    static ref TLS_FEATURE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.24").unwrap();
    static ref PRECERT_POISON_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.11129.2.4.3").unwrap();
    static ref OCSP_NO_CHECK_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.5").unwrap();

    static ref KEY_USAGE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.15").unwrap();
    static ref POLICY_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.36").unwrap();
    static ref EXTENDED_KEY_USAGE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.37").unwrap();
    static ref BASIC_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.19").unwrap();
    static ref SUBJECT_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.14").unwrap();
    static ref INHIBIT_ANY_POLICY_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.54").unwrap();
    static ref CRL_REASON_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.21").unwrap();
    static ref CRL_NUMBER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.20").unwrap();
    static ref DELTA_CRL_INDICATOR_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.27").unwrap();
    static ref SUBJECT_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.17").unwrap();
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

fn parse_name_attribute(
    py: pyo3::Python<'_>,
    attribute: AttributeTypeValue,
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

fn parse_name(py: pyo3::Python<'_>, name: Name) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let py_rdns = pyo3::types::PyList::empty(py);
    for rdn in name {
        let py_attrs = pyo3::types::PySet::empty(py)?;
        for attribute in rdn {
            let na = parse_name_attribute(py, attribute)?;
            py_attrs.add(na)?;
        }
        let py_rdn = x509_module
            .call_method1("RelativeDistinguishedName", (py_attrs,))?
            .to_object(py);
        py_rdns.append(py_rdn)?;
    }
    let py_name = x509_module.call_method1("Name", (py_rdns,))?.to_object(py);
    Ok(py_name)
}

fn parse_general_name(
    py: pyo3::Python<'_>,
    gn: GeneralName,
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
            let ip_addr = ip_module.call_method1("ip_address", (data,))?.to_object(py);
            x509_module
                .call_method1("IPAddress", (ip_addr,))?
                .to_object(py)
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

fn parse_general_names(
    py: pyo3::Python<'_>,
    ext_data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let gns = pyo3::types::PyList::empty(py);
    for gn in asn1::parse_single::<asn1::SequenceOf<GeneralName>>(ext_data)? {
        let py_gn = parse_general_name(py, gn)?;
        gns.append(py_gn)?;
    }
    Ok(gns.to_object(py))
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
        let sans = parse_general_names(py, ext_data)?;
        Ok(x509_module
            .call1("SubjectAlternativeName", (sans,))?
            .to_object(py))
    } else if oid == *TLS_FEATURE_OID {
        let tls_feature_type_to_enum = py
            .import("cryptography.x509.extensions")?
            .getattr("_TLS_FEATURE_TYPE_TO_ENUM")?;

        let features = pyo3::types::PyList::empty(py);
        for feature in asn1::parse_single::<asn1::SequenceOf<u64>>(ext_data)? {
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
        for oid in asn1::parse_single::<asn1::SequenceOf<asn1::ObjectIdentifier>>(ext_data)? {
            let oid_obj = x509_module.call_method1("ObjectIdentifier", (oid.to_string(),))?;
            ekus.append(oid_obj)?;
        }
        Ok(x509_module
            .call1("ExtendedKeyUsage", (ekus,))?
            .to_object(py))
    } else if oid == *KEY_USAGE_OID {
        let kus = asn1::parse_single::<asn1::BitString>(ext_data)?;
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
        let bignum = asn1::parse_single::<asn1::BigUint>(ext_data)?;
        let pynum = big_asn1_uint_to_py(py, bignum)?;
        Ok(x509_module
            .call1("InhibitAnyPolicy", (pynum,))?
            .to_object(py))
    } else if oid == *BASIC_CONSTRAINTS_OID {
        let bc = asn1::parse_single::<BasicConstraints>(ext_data)?;
        Ok(x509_module
            .call1("BasicConstraints", (bc.ca, bc.path_length))?
            .to_object(py))
    } else {
        Ok(py.None())
    }
}

#[pyo3::prelude::pyfunction]
fn parse_crl_entry_extension(
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
        let bignum = asn1::parse_single::<asn1::BigUint>(ext_data)?;
        let pynum = big_asn1_uint_to_py(py, bignum)?;
        Ok(x509_module.call1("CRLNumber", (pynum,))?.to_object(py))
    } else if oid == *DELTA_CRL_INDICATOR_OID {
        let bignum = asn1::parse_single::<asn1::BigUint>(ext_data)?;
        let pynum = big_asn1_uint_to_py(py, bignum)?;
        Ok(x509_module
            .call1("DeltaCRLIndicator", (pynum,))?
            .to_object(py))
    } else {
        Ok(py.None())
    }
}

pub(crate) fn create_submodule(py: pyo3::Python) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "x509")?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_x509_extension))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_crl_entry_extension))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_crl_extension))?;

    Ok(submod)
}
