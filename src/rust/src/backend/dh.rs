// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::encode_der_data;
use crate::backend::utils;
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509;
use cryptography_x509::common;
use foreign_types_shared::ForeignTypeRef;

const MIN_MODULUS_SIZE: u32 = 512;

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.dh")]
struct DHPrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.dh")]
struct DHPublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.dh")]
struct DHParameters {
    dh: openssl::dh::Dh<openssl::pkey::Params>,
}

#[pyo3::prelude::pyfunction]
fn generate_parameters(generator: u32, key_size: u32) -> CryptographyResult<DHParameters> {
    if key_size < MIN_MODULUS_SIZE {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(format!(
                "DH key_size must be at least {} bits",
                MIN_MODULUS_SIZE
            )),
        ));
    }
    if generator != 2 && generator != 5 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("DH generator must be 2 or 5"),
        ));
    }

    let dh = openssl::dh::Dh::generate_params(key_size, generator)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Unable to generate DH parameters"))?;
    Ok(DHParameters { dh })
}

#[pyo3::prelude::pyfunction]
fn private_key_from_ptr(ptr: usize) -> DHPrivateKey {
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    DHPrivateKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::prelude::pyfunction]
fn public_key_from_ptr(ptr: usize) -> DHPublicKey {
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    DHPublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::prelude::pyfunction]
fn from_der_parameters(data: &[u8]) -> CryptographyResult<DHParameters> {
    let asn1_params = asn1::parse_single::<common::DHParams<'_>>(data)?;

    let p = openssl::bn::BigNum::from_slice(asn1_params.p.as_bytes())?;
    let q = asn1_params
        .q
        .map(|q| openssl::bn::BigNum::from_slice(q.as_bytes()))
        .transpose()?;
    let g = openssl::bn::BigNum::from_slice(asn1_params.g.as_bytes())?;

    Ok(DHParameters {
        dh: openssl::dh::Dh::from_pqg(p, q, g)?,
    })
}

#[pyo3::prelude::pyfunction]
fn from_pem_parameters(data: &[u8]) -> CryptographyResult<DHParameters> {
    let parsed = x509::find_in_pem(
        data,
        |p| p.tag == "DH PARAMETERS" || p.tag == "X9.42 DH PARAMETERS",
        "Valid PEM but no BEGIN DH PARAMETERS/END DH PARAMETERS delimiters. Are you sure this is a DH parameters?",
    )?;

    from_der_parameters(&parsed.contents)
}

fn dh_parameters_from_numbers(
    py: pyo3::Python<'_>,
    numbers: &pyo3::PyAny,
) -> CryptographyResult<openssl::dh::Dh<openssl::pkey::Params>> {
    let p = utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "p"))?)?;
    let q = numbers
        .getattr(pyo3::intern!(py, "q"))?
        .extract::<Option<&pyo3::PyAny>>()?
        .map(|v| utils::py_int_to_bn(py, v))
        .transpose()?;
    let g = utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "g"))?)?;

    let dh = openssl::dh::Dh::from_pqg(p, q, g)?;
    if !dh.check_key()? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "DH private numbers did not pass safety checks.",
            ),
        ));
    }

    Ok(dh)
}

#[pyo3::prelude::pyfunction]
fn from_private_numbers(
    py: pyo3::Python<'_>,
    numbers: &pyo3::PyAny,
) -> CryptographyResult<DHPrivateKey> {
    let public_numbers = numbers.getattr(pyo3::intern!(py, "public_numbers"))?;
    let parameter_numbers = public_numbers.getattr(pyo3::intern!(py, "parameter_numbers"))?;

    let dh = dh_parameters_from_numbers(py, parameter_numbers)?;

    let pub_key = utils::py_int_to_bn(py, public_numbers.getattr(pyo3::intern!(py, "y"))?)?;
    let priv_key = utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "x"))?)?;

    let pkey = openssl::pkey::PKey::from_dh(dh.set_key(pub_key, priv_key)?)?;
    Ok(DHPrivateKey { pkey })
}

#[pyo3::prelude::pyfunction]
fn from_public_numbers(
    py: pyo3::Python<'_>,
    numbers: &pyo3::PyAny,
) -> CryptographyResult<DHPublicKey> {
    let parameter_numbers = numbers.getattr(pyo3::intern!(py, "parameter_numbers"))?;
    let dh = dh_parameters_from_numbers(py, parameter_numbers)?;

    let pub_key = utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "y"))?)?;

    let pkey = openssl::pkey::PKey::from_dh(dh.set_public_key(pub_key)?)?;

    Ok(DHPublicKey { pkey })
}

#[pyo3::prelude::pyfunction]
fn from_parameter_numbers(
    py: pyo3::Python<'_>,
    numbers: &pyo3::PyAny,
) -> CryptographyResult<DHParameters> {
    let dh = dh_parameters_from_numbers(py, numbers)?;
    Ok(DHParameters { dh })
}

fn clone_dh<T: openssl::pkey::HasParams>(
    dh: &openssl::dh::Dh<T>,
) -> CryptographyResult<openssl::dh::Dh<openssl::pkey::Params>> {
    let p = dh.prime_p().to_owned()?;
    let q = dh.prime_q().map(|q| q.to_owned()).transpose()?;
    let g = dh.generator().to_owned()?;
    Ok(openssl::dh::Dh::from_pqg(p, q, g)?)
}

#[pyo3::prelude::pymethods]
impl DHPrivateKey {
    #[getter]
    fn key_size(&self) -> i32 {
        self.pkey.dh().unwrap().prime_p().num_bits()
    }

    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        public_key: &DHPublicKey,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let mut deriver = openssl::derive::Deriver::new(&self.pkey)?;
        deriver
            .set_peer(&public_key.pkey)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Error computing shared key."))?;

        Ok(pyo3::types::PyBytes::new_with(py, deriver.len()?, |b| {
            let n = deriver.derive(b).unwrap();

            let pad = b.len() - n;
            if pad > 0 {
                b.copy_within(0..n, pad);
                for c in b.iter_mut().take(pad) {
                    *c = 0;
                }
            }
            Ok(())
        })?)
    }

    fn private_numbers<'p>(&self, py: pyo3::Python<'p>) -> CryptographyResult<&'p pyo3::PyAny> {
        let dh = self.pkey.dh().unwrap();

        let py_p = utils::bn_to_py_int(py, dh.prime_p())?;
        let py_q = dh
            .prime_q()
            .map(|q| utils::bn_to_py_int(py, q))
            .transpose()?;
        let py_g = utils::bn_to_py_int(py, dh.generator())?;

        let py_pub_key = utils::bn_to_py_int(py, dh.public_key())?;
        let py_private_key = utils::bn_to_py_int(py, dh.private_key())?;

        let dh_mod = py.import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.dh"
        ))?;

        let parameter_numbers =
            dh_mod.call_method1(pyo3::intern!(py, "DHParameterNumbers"), (py_p, py_g, py_q))?;
        let public_numbers = dh_mod.call_method1(
            pyo3::intern!(py, "DHPublicNumbers"),
            (py_pub_key, parameter_numbers),
        )?;

        Ok(dh_mod.call_method1(
            pyo3::intern!(py, "DHPrivateNumbers"),
            (py_private_key, public_numbers),
        )?)
    }

    fn public_key(&self) -> CryptographyResult<DHPublicKey> {
        let orig_dh = self.pkey.dh().unwrap();
        let dh = clone_dh(&orig_dh)?;

        let pkey =
            openssl::pkey::PKey::from_dh(dh.set_public_key(orig_dh.public_key().to_owned()?)?)?;

        Ok(DHPublicKey { pkey })
    }

    fn parameters(&self) -> CryptographyResult<DHParameters> {
        Ok(DHParameters {
            dh: clone_dh(&self.pkey.dh().unwrap())?,
        })
    }

    fn private_bytes<'p>(
        slf: &pyo3::PyCell<Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
        format: &pyo3::PyAny,
        encryption_algorithm: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let private_format_class = py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.serialization"
            ))?
            .getattr(pyo3::intern!(py, "PrivateFormat"))?;
        if !format.is(private_format_class.getattr(pyo3::intern!(py, "PKCS8"))?) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "DH private keys support only PKCS8 serialization",
                ),
            ));
        }

        utils::pkey_private_bytes(
            py,
            slf,
            &slf.borrow().pkey,
            encoding,
            format,
            encryption_algorithm,
            true,
        )
    }
}

#[pyo3::prelude::pymethods]
impl DHPublicKey {
    #[getter]
    fn key_size(&self) -> i32 {
        self.pkey.dh().unwrap().prime_p().num_bits()
    }

    fn public_bytes<'p>(
        slf: &pyo3::PyCell<Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
        format: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let public_format_class = py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.serialization"
            ))?
            .getattr(pyo3::intern!(py, "PublicFormat"))?;
        if !format.is(public_format_class.getattr(pyo3::intern!(py, "SubjectPublicKeyInfo"))?) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "DH public keys support only SubjectPublicKeyInfo serialization",
                ),
            ));
        }

        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true)
    }

    fn parameters(&self) -> CryptographyResult<DHParameters> {
        Ok(DHParameters {
            dh: clone_dh(&self.pkey.dh().unwrap())?,
        })
    }

    fn public_numbers<'p>(&self, py: pyo3::Python<'p>) -> CryptographyResult<&'p pyo3::PyAny> {
        let dh = self.pkey.dh().unwrap();

        let py_p = utils::bn_to_py_int(py, dh.prime_p())?;
        let py_q = dh
            .prime_q()
            .map(|q| utils::bn_to_py_int(py, q))
            .transpose()?;
        let py_g = utils::bn_to_py_int(py, dh.generator())?;

        let py_pub_key = utils::bn_to_py_int(py, dh.public_key())?;

        let dh_mod = py.import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.dh"
        ))?;

        let parameter_numbers =
            dh_mod.call_method1(pyo3::intern!(py, "DHParameterNumbers"), (py_p, py_g, py_q))?;

        Ok(dh_mod.call_method1(
            pyo3::intern!(py, "DHPublicNumbers"),
            (py_pub_key, parameter_numbers),
        )?)
    }

    fn __richcmp__(
        &self,
        other: pyo3::PyRef<'_, DHPublicKey>,
        op: pyo3::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => Ok(self.pkey.public_eq(&other.pkey)),
            pyo3::basic::CompareOp::Ne => Ok(!self.pkey.public_eq(&other.pkey)),
            _ => Err(pyo3::exceptions::PyTypeError::new_err("Cannot be ordered")),
        }
    }
}

#[pyo3::prelude::pymethods]
impl DHParameters {
    fn generate_private_key(&self) -> CryptographyResult<DHPrivateKey> {
        let dh = clone_dh(&self.dh)?.generate_key()?;
        Ok(DHPrivateKey {
            pkey: openssl::pkey::PKey::from_dh(dh)?,
        })
    }

    fn parameter_numbers<'p>(&self, py: pyo3::Python<'p>) -> CryptographyResult<&'p pyo3::PyAny> {
        let py_p = utils::bn_to_py_int(py, self.dh.prime_p())?;
        let py_q = self
            .dh
            .prime_q()
            .map(|q| utils::bn_to_py_int(py, q))
            .transpose()?;
        let py_g = utils::bn_to_py_int(py, self.dh.generator())?;

        Ok(py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.asymmetric.dh"
            ))?
            .call_method1(pyo3::intern!(py, "DHParameterNumbers"), (py_p, py_g, py_q))?)
    }

    fn parameter_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &'p pyo3::PyAny,
        format: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let parameter_format_class = py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.serialization"
            ))?
            .getattr(pyo3::intern!(py, "ParameterFormat"))?;
        if !format.is(parameter_format_class.getattr(pyo3::intern!(py, "PKCS3"))?) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Only PKCS3 serialization is supported"),
            ));
        }

        let p_bytes = utils::bn_to_big_endian_bytes(self.dh.prime_p())?;
        let q_bytes = self
            .dh
            .prime_q()
            .map(utils::bn_to_big_endian_bytes)
            .transpose()?;
        let g_bytes = utils::bn_to_big_endian_bytes(self.dh.generator())?;
        let asn1dh_params = common::DHParams {
            p: asn1::BigUint::new(&p_bytes).unwrap(),
            q: q_bytes.as_ref().map(|q| asn1::BigUint::new(q).unwrap()),
            g: asn1::BigUint::new(&g_bytes).unwrap(),
        };
        let data = asn1::write_single(&asn1dh_params)?;
        let tag = if q_bytes.is_none() {
            "DH PARAMETERS"
        } else {
            "X9.42 DH PARAMETERS"
        };
        encode_der_data(py, tag.to_string(), data, encoding)
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "dh")?;
    m.add_function(pyo3::wrap_pyfunction!(generate_parameters, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(private_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(public_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_der_parameters, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_pem_parameters, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_private_numbers, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_public_numbers, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_parameter_numbers, m)?)?;

    m.add_class::<DHPrivateKey>()?;
    m.add_class::<DHPublicKey>()?;
    m.add_class::<DHParameters>()?;

    m.add("MIN_MODULUS_SIZE", MIN_MODULUS_SIZE)?;

    Ok(m)
}
