// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{big_asn1_uint_to_py, PyAsn1Error};
use pyo3::conversion::ToPyObject;
use pyo3::exceptions;
use std::collections::{HashMap, HashSet};

lazy_static::lazy_static! {
    static ref SHA1_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.14.3.2.26").unwrap();
    static ref SHA224_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.4").unwrap();
    static ref SHA256_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.1").unwrap();
    static ref SHA384_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.2").unwrap();
    static ref SHA512_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.3").unwrap();

    static ref OIDS_TO_HASH: HashMap<&'static asn1::ObjectIdentifier<'static>, &'static str> = {
        let mut h = HashMap::new();
        h.insert(&*SHA1_OID, "SHA1");
        h.insert(&*SHA224_OID, "SHA224");
        h.insert(&*SHA256_OID, "SHA256");
        h.insert(&*SHA384_OID, "SHA384");
        h.insert(&*SHA512_OID, "SHA512");
        h
    };

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
fn load_der_ocsp_request(_py: pyo3::Python<'_>, data: &[u8]) -> Result<OCSPRequest, PyAsn1Error> {
    let raw = OwnedRawOCSPRequest::try_new(data.to_vec(), |data| asn1::parse_single(data))?;

    if raw.borrow_value().tbs_request.request_list.clone().count() != 1 {
        return Err(PyAsn1Error::from(
            exceptions::PyNotImplementedError::new_err(
                "OCSP request contains more than one request",
            ),
        ));
    }

    Ok(OCSPRequest {
        raw,
        cached_extensions: None,
    })
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
            .unwrap()
            .req_cert)
    }
}

fn parse_and_cache_extensions<
    'p,
    F: Fn(&asn1::ObjectIdentifier, &[u8]) -> Result<Option<&'p pyo3::PyAny>, PyAsn1Error>,
>(
    py: pyo3::Python<'p>,
    cached_extensions: &mut Option<pyo3::PyObject>,
    raw_exts: &Option<Extensions>,
    parse_ext: F,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    if let Some(cached) = cached_extensions {
        return Ok(cached.clone_ref(py));
    }

    let x509_module = py.import("cryptography.x509")?;
    let exts = pyo3::types::PyList::empty(py);
    let mut seen_oids = HashSet::new();
    if let Some(raw_exts) = raw_exts {
        for raw_ext in raw_exts.clone() {
            let critical = match raw_ext.critical {
                // Explicitly encoded default
                Some(false) => unimplemented!(),
                Some(true) => true,
                None => false,
            };
            let oid_obj =
                x509_module.call_method1("ObjectIdentifier", (raw_ext.extn_id.to_string(),))?;

            if seen_oids.contains(&raw_ext.extn_id) {
                return Err(PyAsn1Error::from(pyo3::PyErr::from_instance(
                    x509_module.call_method1(
                        "DuplicateExtension",
                        (
                            format!("Duplicate {} extension found", raw_ext.extn_id),
                            oid_obj,
                        ),
                    )?,
                )));
            }

            let extn_value = match parse_ext(&raw_ext.extn_id, raw_ext.extn_value)? {
                Some(e) => e,
                None => x509_module
                    .call_method1("UnrecognizedExtension", (oid_obj, raw_ext.extn_value))?,
            };
            exts.append(x509_module.call_method1("Extension", (oid_obj, critical, extn_value))?)?;
            seen_oids.insert(raw_ext.extn_id);
        }
    }
    let extensions = x509_module
        .call_method1("Extensions", (exts,))?
        .to_object(py);
    *cached_extensions = Some(extensions.clone_ref(py));
    Ok(extensions)
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
        match OIDS_TO_HASH.get(&cert_id.hash_algorithm.oid) {
            Some(alg_name) => Ok(hashes.call0(alg_name)?),
            None => {
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
    }

    #[getter]
    fn serial_number<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        Ok(big_asn1_uint_to_py(py, self.cert_id()?.serial_number)?)
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python) -> Result<pyo3::PyObject, PyAsn1Error> {
        let x509_module = py.import("cryptography.x509")?;
        parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &self.raw.borrow_value().tbs_request.request_extensions,
            |oid, value| {
                if oid == &*NONCE_OID {
                    // This is a disaster. RFC 2560 says that the contents of the nonce is
                    // just the raw extension value. This is nonsense, since they're always
                    // supposed to be ASN.1 TLVs. RFC 6960 correctly specifies that the
                    // nonce is an OCTET STRING, and so you should unwrap the TLV to get
                    // the nonce. For now we just implement the old behavior, even though
                    // it's deranged.
                    Ok(Some(x509_module.call_method1("OCSPNonce", (value,))?))
                } else {
                    Ok(None)
                }
            },
        )
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
    ) -> Result<&'p pyo3::types::PyBytes, PyAsn1Error> {
        let der = py
            .import("cryptography.hazmat.primitives.serialization")?
            .getattr("Encoding")?
            .getattr("DER")?;
        if encoding != der {
            return Err(PyAsn1Error::from(exceptions::PyValueError::new_err(
                "The only allowed encoding value is Encoding.DER",
            )));
        }
        let result = asn1::write_single(self.raw.borrow_value());
        Ok(pyo3::types::PyBytes::new(py, &result))
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct RawOCSPRequest<'a> {
    tbs_request: TBSRequest<'a>,
    // Parsing out the full structure, which includes the entirety of a
    // certificate is more trouble than it's worth, since it's not in the
    // Python API.
    #[explicit(0)]
    _optional_signature: Option<asn1::Sequence<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct TBSRequest<'a> {
    #[explicit(0)]
    _version: Option<u8>,
    // This is virtually unused, not supported until GeneralName is implemented
    // and used elsewhere.
    // #[explicit(1)]
    // _requestor_name: Option<GeneralName<'a>>,
    request_list: asn1::SequenceOf<'a, Request<'a>>,
    #[explicit(2)]
    request_extensions: Option<Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct Request<'a> {
    req_cert: CertID<'a>,
    #[explicit(0)]
    _single_request_extensions: Option<Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct CertID<'a> {
    hash_algorithm: AlgorithmIdentifier<'a>,
    issuer_name_hash: &'a [u8],
    issuer_key_hash: &'a [u8],
    serial_number: asn1::BigUint<'a>,
}

type Extensions<'a> = asn1::SequenceOf<'a, Extension<'a>>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct AlgorithmIdentifier<'a> {
    oid: asn1::ObjectIdentifier<'a>,
    _params: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct Extension<'a> {
    extn_id: asn1::ObjectIdentifier<'a>,
    // default false
    critical: Option<bool>,
    extn_value: &'a [u8],
}

#[pyo3::prelude::pyfunction]
fn parse_ocsp_resp_extension(
    py: pyo3::Python<'_>,
    der_oid: &[u8],
    ext_data: &[u8],
) -> pyo3::PyResult<pyo3::PyObject> {
    let oid = asn1::ObjectIdentifier::from_der(der_oid).unwrap();

    let x509_module = py.import("cryptography.x509")?;
    if oid == *NONCE_OID {
        // This is a disaster. RFC 2560 says that the contents of the nonce is
        // just the raw extension value. This is nonsense, since they're always
        // supposed to be ASN.1 TLVs. RFC 6960 correctly specifies that the
        // nonce is an OCTET STRING, and so you should unwrap the TLV to get
        // the nonce. For now we just implement the old behavior, even though
        // it's deranged.
        Ok(x509_module
            .call_method1("OCSPNonce", (ext_data,))?
            .to_object(py))
    } else {
        let oid_obj = x509_module.call_method1("ObjectIdentifier", (oid.to_string(),))?;
        Ok(x509_module
            .call_method1("UnrecognizedExtension", (oid_obj, ext_data))?
            .to_object(py))
    }
}

pub(crate) fn create_submodule(py: pyo3::Python) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "ocsp")?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(load_der_ocsp_request))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_ocsp_resp_extension))?;

    Ok(submod)
}
