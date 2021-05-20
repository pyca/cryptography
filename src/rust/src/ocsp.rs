// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::conversion::ToPyObject;
use crate::asn1::{big_asn1_uint_to_py, PyAsn1Error};

lazy_static::lazy_static! {
    static ref SHA1_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.14.3.2.26").unwrap();
    static ref SHA224_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.4").unwrap();
    static ref SHA256_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.1").unwrap();
    static ref SHA384_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.2").unwrap();
    static ref SHA512_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.3").unwrap();

    static ref NONCE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.2").unwrap();
}

#[ouroboros::self_referencing]
struct OwnedRawOCSPRequest {
    data: Vec<u8>,
    #[borrows(data)]
    #[covariant]
    value: RawOCSPRequest<'this>,
}

#[pyo3::prelude::pyfunction]
fn load_der_ocsp_request(py: pyo3::Python<'_>, data: &[u8]) -> Result<OCSPRequest, PyAsn1Error> {
    let raw = OwnedRawOCSPRequest::try_new(data.to_vec(), |data| asn1::parse_single(data))?;

    Ok(OCSPRequest { raw, cached_extensions: None })
}

#[pyo3::prelude::pyclass]
struct OCSPRequest {
    raw: OwnedRawOCSPRequest,

    cached_extensions: Option<pyo3::PyObject>,
}

impl OCSPRequest {
    fn cert_id(&self) -> Result<CertID, PyAsn1Error> {
        Ok(self
            .raw
            .borrow_value()
            .tbs_request
            .request_list
            .clone()
            .next()
            .unwrap()?
            .req_cert)
    }
}

#[pyo3::prelude::pymethods]
impl OCSPRequest {
    #[getter]
    fn issuer_name_hash(&self) -> Result<&[u8], PyAsn1Error> {
        Ok(self.cert_id()?.issuer_name_hash)
    }

    #[getter]
    fn issuer_key_hash(&self) -> Result<&[u8], PyAsn1Error> {
        Ok(self.cert_id()?.issuer_key_hash)
    }

    #[getter]
    fn hash_algorithm<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let cert_id = self.cert_id()?;

        let hashes = py.import("cryptography.hazmat.primitives.hashes")?;
        if cert_id.hash_algorithm.oid == *SHA1_OID {
            Ok(hashes.call0("SHA1")?)
        } else if cert_id.hash_algorithm.oid == *SHA224_OID {
            Ok(hashes.call0("SHA224")?)
        } else if cert_id.hash_algorithm.oid == *SHA256_OID {
            Ok(hashes.call0("SHA256")?)
        } else if cert_id.hash_algorithm.oid == *SHA384_OID {
            Ok(hashes.call0("SHA384")?)
        } else if cert_id.hash_algorithm.oid == *SHA512_OID {
            Ok(hashes.call0("SHA512")?)
        } else {
            let exceptions = py.import("cryptography.exceptions")?;
            Err(PyAsn1Error::from(pyo3::PyErr::from_instance(
                exceptions.call1(
                    "UnsupportedAlgorithm",
                    (format!(
                        "Signature algorithm OID: {} not recognized",
                        cert_id.hash_algorithm.oid
                    ),),
                )?,
            )))
        }
    }

    #[getter]
    fn serial_number<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        Ok(big_asn1_uint_to_py(py, self.cert_id()?.serial_number)?)
    }

    #[getter]
    fn extensions<'p>(&mut self, py: pyo3::Python<'p>) -> Result<pyo3::PyObject, PyAsn1Error> {
        if let Some(cached) = &self.cached_extensions {
            return Ok(cached.clone_ref(py));
        }

        let x509_module = py.import("cryptography.x509")?;
        let exts = pyo3::types::PyList::empty(py);
        if let Some(raw_exts) = &self.raw.borrow_value().tbs_request.request_extensions {
            for raw_ext in raw_exts.clone() {
                let raw_ext = raw_ext?;
                let critical = match raw_ext.critical {
                    // Explicitly encoded default
                    Some(false) => unimplemented!(),
                    Some(true) => true,
                    None => false,
                };
                let oid_obj = x509_module.call_method1("ObjectIdentifier", (raw_ext.extn_id.to_string(),))?;
                let extn_value = if raw_ext.extn_id == *NONCE_OID {
                    // This is a disaster. RFC 2560 says that the contents of the nonce is
                    // just the raw extension value. This is nonsense, since they're always
                    // supposed to be ASN.1 TLVs. RFC 6960 correctly specifies that the
                    // nonce is an OCTET STRING, and so you should unwrap the TLV to get
                    // the nonce. For now we just implement the old behavior, even though
                    // it's deranged.
                    x509_module
                        .call_method1("OCSPNonce", (raw_ext.extn_value,))?
                } else {
                    x509_module
                        .call_method1("UnrecognizedExtension", (oid_obj, raw_ext.extn_value))?
                };

                exts.append(x509_module.call_method1("Extension", (oid_obj, critical, extn_value))?)?;
            }
        }
        let extensions = x509_module.call_method1("Extensions", (exts,))?.to_object(py);
        self.cached_extensions = Some(extensions.clone_ref(py));
        Ok(extensions)
    }
}

#[derive(asn1::Asn1Read)]
struct RawOCSPRequest<'a> {
    tbs_request: TBSRequest<'a>,
    #[explicit(0)]
    optional_signature: Option<Signature<'a>>,
}

#[derive(asn1::Asn1Read)]
struct TBSRequest<'a> {
    #[explicit(0)]
    version: Option<u8>,
    #[explicit(1)]
    requestor_name: Option<GeneralName<'a>>,
    request_list: asn1::SequenceOf<'a, Request<'a>>,
    #[explicit(2)]
    request_extensions: Option<Extensions<'a>>,
}

#[derive(asn1::Asn1Read)]
struct Request<'a> {
    req_cert: CertID<'a>,
    #[explicit(0)]
    single_request_extensions: Option<Extensions<'a>>,
}

#[derive(asn1::Asn1Read)]
struct CertID<'a> {
    hash_algorithm: AlgorithmIdentifier<'a>,
    issuer_name_hash: &'a [u8],
    issuer_key_hash: &'a [u8],
    serial_number: asn1::BigUint<'a>,
}

#[derive(asn1::Asn1Read)]
struct Signature<'a> {
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: asn1::BitString<'a>,
    // This is just an opaque SEQUENCE, because we don't want to parse out all
    // of certificates.
    #[explicit(0)]
    certs: Option<asn1::Sequence<'a>>,
}

type Extensions<'a> = asn1::SequenceOf<'a, Extension<'a>>;

#[derive(asn1::Asn1Read)]
struct AlgorithmIdentifier<'a> {
    oid: asn1::ObjectIdentifier<'a>,
    params: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Read)]
struct Extension<'a> {
    extn_id: asn1::ObjectIdentifier<'a>,
    // default false
    critical: Option<bool>,
    extn_value: &'a [u8],
}

fn parse_implicit<'a, T: asn1::SimpleAsn1Readable<'a>>(
    data: &'a [u8],
    tag: u8,
) -> asn1::ParseResult<T> {
    asn1::parse(data, |p| {
        Ok(p.read_optional_implicit_element::<T>(tag)?.unwrap())
    })
}

// This is a manual implementation of the follow, until we can use const
// generics
// asn1::Choice9<
//     asn1::Implicit<OtherName, 0>>,
//     asn1::Implicit<asn1::IA5String, 1>>,
//     asn1::Implicit<asn1::IA5String, 2>>,
//     asn1::Implicit<ORAddress, 3>>,
//     asn1::Implicit<Name, 4>>,
//     asn1::Implicit<EDIPartyName, 5>>,
//     asn1::Implicit<IA5String, 6>>,
//     asn1::Implicit<IPAddress, 7>>,
//     asn1::Implicit<RegisteredID, 8>>,
// >
enum GeneralName<'a> {
    // OtherName(OtherName<'a>),
    RFC822Name(asn1::IA5String<'a>),
    DNSName(asn1::IA5String<'a>),
    // X400Name(ORAddress),
    // DirectoryName(Name<'a>),
    // EDIPartyName(EDIPartyName<'a>),
    UniformResourceIdentifier(asn1::IA5String<'a>),
    IPAddress(&'a [u8]),
    RegisteredID(asn1::ObjectIdentifier<'a>),
}
impl<'a> asn1::Asn1Readable<'a> for GeneralName<'a> {
    fn parse(p: &mut asn1::Parser<'a>) -> asn1::ParseResult<Self> {
        let tlv = p.read_element::<asn1::Tlv>()?;
        Ok(match tlv.tag() {
            0 => unimplemented!(),
            1 => GeneralName::RFC822Name(parse_implicit(tlv.data(), 1)?),
            2 => GeneralName::DNSName(parse_implicit(tlv.data(), 2)?),
            3 => unimplemented!(),
            4 => unimplemented!(),
            5 => unimplemented!(),
            6 => GeneralName::UniformResourceIdentifier(parse_implicit(tlv.data(), 6)?),
            7 => GeneralName::IPAddress(parse_implicit(tlv.data(), 7)?),
            8 => GeneralName::RegisteredID(parse_implicit(tlv.data(), 8)?),
            _ => return Err(asn1::ParseError::UnexpectedTag { actual: tlv.tag() }),
        })
    }

    fn can_parse(tag: u8) -> bool {
        matches!(tag, 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8)
    }
}

pub(crate) fn create_submodule(py: pyo3::Python) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "ocsp")?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(load_der_ocsp_request))?;

    Ok(submod)
}
