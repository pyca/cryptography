// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::{hashes, hmac, keys};
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;
use crate::x509::certificate::Certificate;
use crate::{types, x509};
use cryptography_x509::common::Utf8StoredBMPString;
use pyo3::prelude::{PyAnyMethods, PyBytesMethods, PyListMethods, PyModuleMethods};
use pyo3::IntoPy;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[pyo3::prelude::pyclass(frozen)]
struct PKCS12Certificate {
    #[pyo3(get)]
    certificate: pyo3::Py<Certificate>,
    #[pyo3(get)]
    friendly_name: Option<pyo3::Py<pyo3::types::PyBytes>>,
}

#[pyo3::prelude::pymethods]
impl PKCS12Certificate {
    #[new]
    fn new(
        cert: pyo3::Py<Certificate>,
        friendly_name: Option<pyo3::Py<pyo3::types::PyBytes>>,
    ) -> PKCS12Certificate {
        PKCS12Certificate {
            certificate: cert,
            friendly_name,
        }
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        let friendly_name_eq = match (&self.friendly_name, &other.friendly_name) {
            (Some(a), Some(b)) => a.bind(py).eq(b.bind(py))?,
            (None, None) => true,
            _ => false,
        };
        Ok(friendly_name_eq && self.certificate.bind(py).eq(other.certificate.bind(py))?)
    }

    fn __hash__(&self, py: pyo3::Python<'_>) -> CryptographyResult<u64> {
        let mut hasher = DefaultHasher::new();
        self.certificate.bind(py).hash()?.hash(&mut hasher);
        match &self.friendly_name {
            Some(v) => v.bind(py).hash()?.hash(&mut hasher),
            None => None::<u32>.hash(&mut hasher),
        };
        Ok(hasher.finish())
    }

    fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        let py_friendly_name_repr;
        let friendly_name_repr = match &self.friendly_name {
            Some(v) => {
                py_friendly_name_repr = v
                    .bind(py)
                    .repr()?
                    .extract::<pyo3::pybacked::PyBackedStr>()?;
                &*py_friendly_name_repr
            }
            None => "None",
        };
        Ok(format!(
            "<PKCS12Certificate({}, friendly_name={})>",
            self.certificate.bind(py).str()?,
            friendly_name_repr
        ))
    }
}

#[allow(dead_code)]
const KDF_ENCRYPTION_KEY_ID: u8 = 1;
#[allow(dead_code)]
const KDF_IV_ID: u8 = 2;
const KDF_MAC_KEY_ID: u8 = 3;

fn pkcs12_kdf(
    pass: &[u8],
    salt: &[u8],
    id: u8,
    rounds: u64,
    key_len: usize,
    hash_alg: openssl::hash::MessageDigest,
) -> CryptographyResult<Vec<u8>> {
    // Encode the password as big-endian UTF-16 with NUL trailer
    let pass = std::str::from_utf8(pass)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("key must be valid UTF-8"))?
        .encode_utf16()
        .chain([0])
        .flat_map(|v| v.to_be_bytes())
        .collect::<Vec<u8>>();

    // Comments are borrowed from BoringSSL.
    // In the spec, |block_size| is called "v", but measured in bits.
    let block_size = hash_alg.block_size();

    // 1. Construct a string, D (the "diversifier"), by concatenating v/8 copies
    // of ID.
    let d = vec![id; block_size];

    // 2. Concatenate copies of the salt together to create a string S of length
    // v(ceiling(s/v)) bits (the final copy of the salt may be truncated to
    // create S). Note that if the salt is the empty string, then so is S.
    //
    // 3. Concatenate copies of the password together to create a string P of
    // length v(ceiling(p/v)) bits (the final copy of the password may be
    // truncated to create P).  Note that if the password is the empty string,
    // then so is P.
    //
    // 4. Set I=S||P to be the concatenation of S and P.
    let s_len = block_size * ((salt.len() + block_size - 1) / block_size);
    let p_len = block_size * ((pass.len() + block_size - 1) / block_size);

    let mut init_key = vec![0; s_len + p_len];
    for i in 0..s_len {
        init_key[i] = salt[i % salt.len()];
    }
    for i in 0..p_len {
        init_key[i + s_len] = pass[i % pass.len()];
    }

    let mut result = vec![0; key_len];
    let mut pos = 0;
    loop {
        // A. Set A_i=H^r(D||I). (i.e., the r-th hash of D||I,
        // H(H(H(... H(D||I))))

        let mut h = openssl::hash::Hasher::new(hash_alg)?;
        h.update(&d)?;
        h.update(&init_key)?;
        let mut a = h.finish()?;

        for _ in 1..rounds {
            let mut h = openssl::hash::Hasher::new(hash_alg)?;
            h.update(&a)?;
            a = h.finish()?;
        }

        let to_add = a.len().min(result.len() - pos);
        result[pos..pos + to_add].copy_from_slice(&a[..to_add]);
        pos += to_add;
        if pos == result.len() {
            break;
        }

        // B. Concatenate copies of A_i to create a string B of length v bits (the
        // final copy of A_i may be truncated to create B).
        let mut b = vec![0; block_size];
        for i in 0..block_size {
            b[i] = a[i % a.len()];
        }

        // C. Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit blocks,
        // where k=ceiling(s/v)+ceiling(p/v), modify I by setting I_j=(I_j+B+1) mod
        // 2^v for each j.
        assert!(init_key.len() % block_size == 0);
        let mut j = 0;
        while j < init_key.len() {
            let mut carry = 1u16;
            let mut k = block_size - 1;
            loop {
                carry += init_key[k + j] as u16 + b[k] as u16;
                init_key[j + k] = carry as u8;
                carry >>= 8;
                if k == 0 {
                    break;
                }
                k -= 1;
            }
            j += block_size;
        }
    }

    Ok(result)
}

fn friendly_name_attributes(
    friendly_name: Option<&[u8]>,
) -> CryptographyResult<
    Option<
        asn1::SetOfWriter<
            '_,
            cryptography_x509::pkcs12::Attribute<'_>,
            Vec<cryptography_x509::pkcs12::Attribute<'_>>,
        >,
    >,
> {
    if let Some(name) = friendly_name {
        let name_str = std::str::from_utf8(name).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("friendly_name must be valid UTF-8")
        })?;

        Ok(Some(asn1::SetOfWriter::new(vec![
            cryptography_x509::pkcs12::Attribute {
                _attr_id: asn1::DefinedByMarker::marker(),
                attr_values: cryptography_x509::pkcs12::AttributeSet::FriendlyName(
                    asn1::SetOfWriter::new([Utf8StoredBMPString::new(name_str)]),
                ),
            },
        ])))
    } else {
        Ok(None)
    }
}

fn cert_to_bag<'a>(
    cert: &'a Certificate,
    friendly_name: Option<&'a [u8]>,
) -> CryptographyResult<cryptography_x509::pkcs12::SafeBag<'a>> {
    Ok(cryptography_x509::pkcs12::SafeBag {
        _bag_id: asn1::DefinedByMarker::marker(),
        bag_value: asn1::Explicit::new(cryptography_x509::pkcs12::BagValue::CertBag(
            cryptography_x509::pkcs12::CertBag {
                _cert_id: asn1::DefinedByMarker::marker(),
                cert_value: asn1::Explicit::new(cryptography_x509::pkcs12::CertType::X509(
                    asn1::OctetStringEncoded::new(cert.raw.borrow_dependent().clone()),
                )),
            },
        )),
        attributes: friendly_name_attributes(friendly_name)?,
    })
}

fn decode_encryption_algorithm(
    py: pyo3::Python<'_>,
) -> CryptographyResult<(&[u8], pyo3::Bound<'_, pyo3::PyAny>, u64)> {
    let default_hmac_alg = types::SHA256.get(py)?.call0()?;
    let default_hmac_kdf_iter = 2048;

    Ok((b"", default_hmac_alg, default_hmac_kdf_iter))
}

#[derive(pyo3::FromPyObject)]
enum CertificateOrPKCS12Certificate {
    Certificate(pyo3::Py<Certificate>),
    PKCS12Certificate(pyo3::Py<PKCS12Certificate>),
}

#[pyo3::prelude::pyfunction]
#[pyo3(signature = (name, key, cert, cas))]
fn serialize_key_and_certificates<'p>(
    py: pyo3::Python<'p>,
    name: Option<&[u8]>,
    key: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    cert: Option<&Certificate>,
    cas: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let (password, mac_algorithm, mac_kdf_iter) = decode_encryption_algorithm(py)?;

    let mut auth_safe_contents = vec![];
    let (cert_bag_contents, key_bag_contents);
    let mut ca_certs = vec![];
    if cert.is_some() || cas.is_some() {
        let mut cert_bags = vec![];

        if let Some(cert) = cert {
            cert_bags.push(cert_to_bag(cert, name)?);
        }

        if let Some(cas) = cas {
            for cert in cas.iter()? {
                ca_certs.push(cert?.extract::<CertificateOrPKCS12Certificate>()?);
            }

            for cert in &ca_certs {
                let bag = match cert {
                    CertificateOrPKCS12Certificate::Certificate(c) => cert_to_bag(c.get(), None)?,
                    CertificateOrPKCS12Certificate::PKCS12Certificate(c) => cert_to_bag(
                        c.get().certificate.get(),
                        c.get().friendly_name.as_ref().map(|v| v.as_bytes(py)),
                    )?,
                };
                cert_bags.push(bag);
            }
        }

        cert_bag_contents = asn1::write_single(&asn1::SequenceOfWriter::new(cert_bags))?;
        auth_safe_contents.push(cryptography_x509::pkcs7::ContentInfo {
            _content_type: asn1::DefinedByMarker::marker(),
            content: cryptography_x509::pkcs7::Content::Data(Some(asn1::Explicit::new(
                &cert_bag_contents,
            ))),
        });
    }

    if let Some(key) = key {
        let der = types::ENCODING_DER.get(py)?;
        let pkcs8 = types::PRIVATE_FORMAT_PKCS8.get(py)?;
        let no_encryption = types::NO_ENCRYPTION.get(py)?.call0()?;

        let pkcs8_bytes = key
            .call_method1(
                pyo3::intern!(py, "private_bytes"),
                (der, pkcs8, no_encryption),
            )?
            .extract::<pyo3::pybacked::PyBackedBytes>()?;
        let pkcs8_tlv = asn1::parse_single(&pkcs8_bytes)?;

        let key_bag = cryptography_x509::pkcs12::SafeBag {
            _bag_id: asn1::DefinedByMarker::marker(),
            bag_value: asn1::Explicit::new(cryptography_x509::pkcs12::BagValue::KeyBag(pkcs8_tlv)),
            attributes: friendly_name_attributes(name)?,
        };

        key_bag_contents = asn1::write_single(&asn1::SequenceOfWriter::new([key_bag]))?;
        auth_safe_contents.push(cryptography_x509::pkcs7::ContentInfo {
            _content_type: asn1::DefinedByMarker::marker(),
            content: cryptography_x509::pkcs7::Content::Data(Some(asn1::Explicit::new(
                &key_bag_contents,
            ))),
        });
    }

    let auth_safe_content = asn1::write_single(&asn1::SequenceOfWriter::new(auth_safe_contents))?;

    let salt = types::OS_URANDOM
        .get(py)?
        .call1((8,))?
        .extract::<pyo3::pybacked::PyBackedBytes>()?;
    let mac_algorithm_md = hashes::message_digest_from_algorithm(py, &mac_algorithm)?;
    let mac_key = pkcs12_kdf(
        password,
        &salt,
        KDF_MAC_KEY_ID,
        mac_kdf_iter,
        mac_algorithm_md.size(),
        mac_algorithm_md,
    )?;
    let mac_digest = {
        let mut h = hmac::Hmac::new_bytes(py, &mac_key, &mac_algorithm)?;
        h.update_bytes(&auth_safe_content)?;
        h.finalize(py)?
    };
    let mac_algorithm_identifier = crate::x509::ocsp::HASH_NAME_TO_ALGORITHM_IDENTIFIERS
        [&*mac_algorithm
            .getattr(pyo3::intern!(py, "name"))?
            .extract::<pyo3::pybacked::PyBackedStr>()?]
        .clone();

    let p12 = cryptography_x509::pkcs12::Pfx {
        version: 3,
        auth_safe: cryptography_x509::pkcs7::ContentInfo {
            _content_type: asn1::DefinedByMarker::marker(),
            content: cryptography_x509::pkcs7::Content::Data(Some(asn1::Explicit::new(
                &auth_safe_content,
            ))),
        },
        mac_data: Some(cryptography_x509::pkcs12::MacData {
            mac: cryptography_x509::pkcs7::DigestInfo {
                algorithm: mac_algorithm_identifier,
                digest: mac_digest.as_bytes(),
            },
            salt: &salt,
            iterations: mac_kdf_iter,
        }),
    };
    Ok(pyo3::types::PyBytes::new_bound(
        py,
        &asn1::write_single(&p12)?,
    ))
}

fn decode_p12(
    data: CffiBuf<'_>,
    password: Option<CffiBuf<'_>>,
) -> CryptographyResult<openssl::pkcs12::ParsedPkcs12_2> {
    let p12 = openssl::pkcs12::Pkcs12::from_der(data.as_bytes()).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("Could not deserialize PKCS12 data")
    })?;

    let password = if let Some(p) = password.as_ref() {
        std::str::from_utf8(p.as_bytes())
            .map_err(|_| pyo3::exceptions::PyUnicodeDecodeError::new_err(()))?
    } else {
        // Treat `password=None` the same as empty string. They're actually
        // not the same in PKCS#12, but OpenSSL transparently handles them the
        // same.
        ""
    };
    let parsed = p12
        .parse2(password)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid password or PKCS12 data"))?;

    Ok(parsed)
}

#[pyo3::prelude::pyfunction]
fn load_key_and_certificates<'p>(
    py: pyo3::Python<'p>,
    data: CffiBuf<'_>,
    password: Option<CffiBuf<'_>>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<(
    pyo3::PyObject,
    Option<x509::certificate::Certificate>,
    pyo3::Bound<'p, pyo3::types::PyList>,
)> {
    let _ = backend;

    let p12 = decode_p12(data, password)?;

    let private_key = if let Some(pkey) = p12.pkey {
        keys::private_key_from_pkey(py, &pkey, false)?
    } else {
        py.None()
    };
    let cert = if let Some(ossl_cert) = p12.cert {
        let cert_der = pyo3::types::PyBytes::new_bound(py, &ossl_cert.to_der()?).unbind();
        Some(x509::certificate::load_der_x509_certificate(
            py, cert_der, None,
        )?)
    } else {
        None
    };
    let additional_certs = pyo3::types::PyList::empty_bound(py);
    if let Some(ossl_certs) = p12.ca {
        cfg_if::cfg_if! {
            if #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_300_OR_GREATER, CRYPTOGRAPHY_IS_BORINGSSL
            ))] {
                let it = ossl_certs.iter();
            } else {
                let it = ossl_certs.iter().rev();
            }
        };

        for ossl_cert in it {
            let cert_der = pyo3::types::PyBytes::new_bound(py, &ossl_cert.to_der()?).unbind();
            let cert = x509::certificate::load_der_x509_certificate(py, cert_der, None)?;
            additional_certs.append(cert.into_py(py))?;
        }
    }

    Ok((private_key, cert, additional_certs))
}

#[pyo3::prelude::pyfunction]
fn load_pkcs12<'p>(
    py: pyo3::Python<'p>,
    data: CffiBuf<'_>,
    password: Option<CffiBuf<'_>>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let _ = backend;

    let p12 = decode_p12(data, password)?;

    let private_key = if let Some(pkey) = p12.pkey {
        keys::private_key_from_pkey(py, &pkey, false)?
    } else {
        py.None()
    };
    let cert = if let Some(ossl_cert) = p12.cert {
        let cert_der = pyo3::types::PyBytes::new_bound(py, &ossl_cert.to_der()?).unbind();
        let cert = x509::certificate::load_der_x509_certificate(py, cert_der, None)?;
        let alias = ossl_cert
            .alias()
            .map(|a| pyo3::types::PyBytes::new_bound(py, a).unbind());

        PKCS12Certificate::new(pyo3::Py::new(py, cert)?, alias).into_py(py)
    } else {
        py.None()
    };
    let additional_certs = pyo3::types::PyList::empty_bound(py);
    if let Some(ossl_certs) = p12.ca {
        cfg_if::cfg_if! {
            if #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_300_OR_GREATER, CRYPTOGRAPHY_IS_BORINGSSL
            ))] {
                let it = ossl_certs.iter();
            } else {
                let it = ossl_certs.iter().rev();
            }
        };

        for ossl_cert in it {
            let cert_der = pyo3::types::PyBytes::new_bound(py, &ossl_cert.to_der()?).unbind();
            let cert = x509::certificate::load_der_x509_certificate(py, cert_der, None)?;
            let alias = ossl_cert
                .alias()
                .map(|a| pyo3::types::PyBytes::new_bound(py, a).unbind());

            let p12_cert = PKCS12Certificate::new(pyo3::Py::new(py, cert)?, alias).into_py(py);
            additional_certs.append(p12_cert)?;
        }
    }

    Ok(types::PKCS12KEYANDCERTIFICATES
        .get(py)?
        .call1((private_key, cert, additional_certs))?)
}

pub(crate) fn create_submodule(
    py: pyo3::Python<'_>,
) -> pyo3::PyResult<pyo3::Bound<'_, pyo3::prelude::PyModule>> {
    let submod = pyo3::prelude::PyModule::new_bound(py, "pkcs12")?;

    submod.add_function(pyo3::wrap_pyfunction_bound!(
        load_key_and_certificates,
        &submod
    )?)?;
    submod.add_function(pyo3::wrap_pyfunction_bound!(load_pkcs12, &submod)?)?;
    submod.add_function(pyo3::wrap_pyfunction_bound!(
        serialize_key_and_certificates,
        &submod
    )?)?;

    submod.add_class::<PKCS12Certificate>()?;

    Ok(submod)
}

#[cfg(test)]
mod tests {
    use super::{pkcs12_kdf, KDF_ENCRYPTION_KEY_ID, KDF_IV_ID, KDF_MAC_KEY_ID};

    #[test]
    fn test_pkcs12_kdf() {
        for (password, salt, id, rounds, key_len, hash, expected_key) in [
            // From https://github.com/RustCrypto/formats/blob/master/pkcs12/tests/kdf.rs
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 100, 32, openssl::hash::MessageDigest::sha256(), b"\xfa\xe4\xd4\x95z<\xc7\x81\xe1\x18\x0b\x9dO\xb7\x9c\x1e\x0c\x85y\xb7F\xa3\x17~[\x07h\xa3\x11\x8b\xf8c" as &[u8]),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_IV_ID, 100, 32, openssl::hash::MessageDigest::sha256(), b"\xe5\xff\x81;\xc6T}\xe5\x15[\x14\xd2\xfa\xda\x85\xb3 \x1a\x97sI\xdbn&\xcc\xc9\x98\xd9\xe8\xf8=l"),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_MAC_KEY_ID, 100, 32, openssl::hash::MessageDigest::sha256(), b"\x13cU\xed\x944Qf\x82SOF\xd69V\xdb_\xf0k\x84G\x02\xc2\xc1\xf3\xb4c!\xe2RJM"),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 100, 20, openssl::hash::MessageDigest::sha256(), b"\xfa\xe4\xd4\x95z<\xc7\x81\xe1\x18\x0b\x9dO\xb7\x9c\x1e\x0c\x85y\xb7"),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_IV_ID, 100, 20, openssl::hash::MessageDigest::sha256(), b"\xe5\xff\x81;\xc6T}\xe5\x15[\x14\xd2\xfa\xda\x85\xb3 \x1a\x97s"),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_MAC_KEY_ID, 100, 20, openssl::hash::MessageDigest::sha256(), b"\x13cU\xed\x944Qf\x82SOF\xd69V\xdb_\xf0k\x84"),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 100, 12, openssl::hash::MessageDigest::sha256(), b"\xfa\xe4\xd4\x95z<\xc7\x81\xe1\x18\x0b\x9d"),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_IV_ID, 100, 12, openssl::hash::MessageDigest::sha256(), b"\xe5\xff\x81;\xc6T}\xe5\x15[\x14\xd2"),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_MAC_KEY_ID, 100, 12, openssl::hash::MessageDigest::sha256(), b"\x13cU\xed\x944Qf\x82SOF"),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 1000, 32, openssl::hash::MessageDigest::sha256(), b"+\x95\xa0V\x9bc\xf6A\xfa\xe1\xef\xca2\xe8M\xb3i\x9a\xb7E@b\x8b\xa6b\x83\xb5\x8c\xf5@\x05'"),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_IV_ID, 1000, 32, openssl::hash::MessageDigest::sha256(), b"dr\xc0\xeb\xad?\xabA#\xe8\xb5\xedx4\xde!\xee\xb2\x01\x87\xb3\xef\xf7\x8a}\x1c\xdf\xfa@4\x85\x1d"),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_MAC_KEY_ID, 1000, 32, openssl::hash::MessageDigest::sha256(), b"?\x91\x13\xf0\\0\xa9\x96\xc4\xa5\x16@\x9b\xda\xc9\xd0e\xf4B\x96\xcc\xd5+\xb7]\xe3\xfc\xfd\xbe+\xf10"),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 1000, 100, openssl::hash::MessageDigest::sha256(), b"+\x95\xa0V\x9bc\xf6A\xfa\xe1\xef\xca2\xe8M\xb3i\x9a\xb7E@b\x8b\xa6b\x83\xb5\x8c\xf5@\x05\'\xd8\xd0\xeb\xe2\xcc\xbfv\x8cQ\xc4\xd8\xfb\xd1\xbb\x15k\xe0l\x1cY\xcb\xb6\x9eD\x05/\xfc77o\xdbG\xb2\xde\x7f\x9eT=\xe9\xd0\x96\xd8\xe5GK\"\x04\x10\xff\x1c]\x8b\xb7\xe5\xbc\x0fa\xba\xea\xa1/\xd0\xda\x1dz\x97\x01r"),
            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 1000, 200, openssl::hash::MessageDigest::sha256(), b"+\x95\xa0V\x9bc\xf6A\xfa\xe1\xef\xca2\xe8M\xb3i\x9a\xb7E@b\x8b\xa6b\x83\xb5\x8c\xf5@\x05\'\xd8\xd0\xeb\xe2\xcc\xbfv\x8cQ\xc4\xd8\xfb\xd1\xbb\x15k\xe0l\x1cY\xcb\xb6\x9eD\x05/\xfc77o\xdbG\xb2\xde\x7f\x9eT=\xe9\xd0\x96\xd8\xe5GK\"\x04\x10\xff\x1c]\x8b\xb7\xe5\xbc\x0fa\xba\xea\xa1/\xd0\xda\x1dz\x97\x01r\x9c\xea`\x14\xd7\xfeb\xa2\xed\x92m\xc3ka0\x7f\x11\x9dd\xed\xbc\xebZ\x9cX\x13;\xbfu\xba\x0b\xef\x00\n\x1aQ\x80\xe4\xb1\xde}\x89\xc8\x95(\xbc\xb7\x89\x9a\x1eF\xfdM\xa0\xd9\xde\x8f\x8ee\xe8\xd0\xd7u\xe3=\x12G\xe7mYj401a\xb2\x19\xf3\x9a\xfd\xa4H\xbfQ\x8a(5\xfc^(\xf0\xb5Z\x1ba7\xa2\xc7\x0c\xf7"),

            ("ge@äheim".as_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 100, 32, openssl::hash::MessageDigest::sha512(), b"\xb1J\x9f\x01\xbf\xd9\xdc\xe4\xc9\xd6m/\xe9\x93~_\xd9\xf1\xaf\xa5\x9e7\no\xa4\xfc\x81\xc1\xcc\x8e\xc8\xee"),

            // From https://cs.opensource.google/go/x/crypto/+/master:pkcs12/pbkdf_test.go
            (b"sesame", b"\xff\xff\xff\xff\xff\xff\xff\xff", KDF_ENCRYPTION_KEY_ID, 2048, 24, openssl::hash::MessageDigest::sha1(), b"\x7c\xd9\xfd\x3e\x2b\x3b\xe7\x69\x1a\x44\xe3\xbe\xf0\xf9\xea\x0f\xb9\xb8\x97\xd4\xe3\x25\xd9\xd1"),
        ] {
            let result = pkcs12_kdf(password, salt, id, rounds, key_len, hash).map_err(|_| ()).unwrap();
            assert_eq!(result, expected_key);
        }
    }

    #[test]
    fn test_pkcs12_kdf_error() {
        // Key is not valid UTF-8
        let result = pkcs12_kdf(
            b"\x91\x82%\xa1",
            b"\x01\x02\x03\x04",
            KDF_ENCRYPTION_KEY_ID,
            100,
            8,
            openssl::hash::MessageDigest::sha256(),
        );
        assert!(matches!(result, Err(_)));
    }
}
