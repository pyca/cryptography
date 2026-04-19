// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::{PyAnyMethods, PyBytesMethods};

use crate::backend::aead::{AesGcm, ChaCha20Poly1305};
use crate::backend::ec;
use crate::backend::hashes::Hash;
use crate::backend::kdf::{hkdf_extract, HkdfExpand};
use crate::backend::x25519;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

const HPKE_VERSION: &[u8] = b"HPKE-v1";
const HPKE_MODE_BASE: u8 = 0x00;

fn u16_length_prefix(length: usize, label: &str) -> CryptographyResult<[u8; 2]> {
    let length = u16::try_from(length).map_err(|_| {
        CryptographyError::from(pyo3::exceptions::PyValueError::new_err(format!(
            "{label} is too large."
        )))
    })?;
    Ok(length.to_be_bytes())
}

mod kem_params {
    pub const X25519_ID: u16 = 0x0020;
    pub const X25519_NSECRET: usize = 32;
    pub const X25519_NENC: usize = 32;

    pub const P256_ID: u16 = 0x0010;
    pub const P256_NSECRET: usize = 32;
    pub const P256_NENC: usize = 65;

    pub const P384_ID: u16 = 0x0011;
    pub const P384_NSECRET: usize = 48;
    pub const P384_NENC: usize = 97;

    pub const P521_ID: u16 = 0x0012;
    pub const P521_NSECRET: usize = 64;
    pub const P521_NENC: usize = 133;

    pub const MLKEM768_ID: u16 = 0x0041;
    pub const MLKEM768_NSECRET: usize = 32;
    pub const MLKEM768_NENC: usize = 1088;

    pub const MLKEM1024_ID: u16 = 0x0042;
    pub const MLKEM1024_NSECRET: usize = 32;
    pub const MLKEM1024_NENC: usize = 1568;
}

mod kdf_params {
    pub const HKDF_SHA256_ID: u16 = 0x0001;
    pub const HKDF_SHA384_ID: u16 = 0x0002;
    pub const HKDF_SHA512_ID: u16 = 0x0003;
    pub const SHAKE128_ID: u16 = 0x0010;
    pub const SHAKE128_HASH_OUTPUT_LENGTH: usize = 32;
    pub const SHAKE256_ID: u16 = 0x0011;
    pub const SHAKE256_HASH_OUTPUT_LENGTH: usize = 64;
}

mod aead_params {
    pub const AES_128_GCM_ID: u16 = 0x0001;
    pub const AES_128_GCM_NK: usize = 16;
    pub const AES_128_GCM_NN: usize = 12;
    pub const AES_128_GCM_NT: usize = 16;

    pub const AES_256_GCM_ID: u16 = 0x0002;
    pub const AES_256_GCM_NK: usize = 32;
    pub const AES_256_GCM_NN: usize = 12;
    pub const AES_256_GCM_NT: usize = 16;

    pub const CHACHA20_POLY1305_ID: u16 = 0x0003;
    pub const CHACHA20_POLY1305_NK: usize = 32;
    pub const CHACHA20_POLY1305_NN: usize = 12;
    pub const CHACHA20_POLY1305_NT: usize = 16;
}

#[allow(clippy::upper_case_acronyms)]
#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    from_py_object,
    module = "cryptography.hazmat.bindings._rust.openssl.hpke"
)]
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum KEM {
    X25519,
    P256,
    P384,
    P521,
    MLKEM768,
    MLKEM1024,
}

impl KEM {
    fn check_ec_public_key(
        py: pyo3::Python<'_>,
        key: &pyo3::Bound<'_, pyo3::PyAny>,
        curve_type: &pyo3::Bound<'_, pyo3::PyAny>,
        kem_name: &str,
        curve_name: &str,
    ) -> CryptographyResult<()> {
        if !key.is_instance(&types::ELLIPTIC_CURVE_PUBLIC_KEY.get(py)?)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "Expected EllipticCurvePublicKey for {}",
                    kem_name
                )),
            ));
        }
        let curve = key.getattr(pyo3::intern!(py, "curve"))?;
        if !curve.is_instance(curve_type)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "Expected EllipticCurvePublicKey on {} for {}",
                    curve_name, kem_name
                )),
            ));
        }
        Ok(())
    }

    fn check_ec_private_key(
        py: pyo3::Python<'_>,
        key: &pyo3::Bound<'_, pyo3::PyAny>,
        curve_type: &pyo3::Bound<'_, pyo3::PyAny>,
        kem_name: &str,
        curve_name: &str,
    ) -> CryptographyResult<()> {
        if !key.is_instance(&types::ELLIPTIC_CURVE_PRIVATE_KEY.get(py)?)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "Expected EllipticCurvePrivateKey for {}",
                    kem_name
                )),
            ));
        }
        let curve = key.getattr(pyo3::intern!(py, "curve"))?;
        if !curve.is_instance(curve_type)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "Expected EllipticCurvePrivateKey on {} for {}",
                    curve_name, kem_name
                )),
            ));
        }
        Ok(())
    }

    fn id(&self) -> u16 {
        match self {
            KEM::X25519 => kem_params::X25519_ID,
            KEM::P256 => kem_params::P256_ID,
            KEM::P384 => kem_params::P384_ID,
            KEM::P521 => kem_params::P521_ID,
            KEM::MLKEM768 => kem_params::MLKEM768_ID,
            KEM::MLKEM1024 => kem_params::MLKEM1024_ID,
        }
    }

    fn secret_length(&self) -> usize {
        match self {
            KEM::X25519 => kem_params::X25519_NSECRET,
            KEM::P256 => kem_params::P256_NSECRET,
            KEM::P384 => kem_params::P384_NSECRET,
            KEM::P521 => kem_params::P521_NSECRET,
            KEM::MLKEM768 => kem_params::MLKEM768_NSECRET,
            KEM::MLKEM1024 => kem_params::MLKEM1024_NSECRET,
        }
    }

    fn enc_length(&self) -> usize {
        match self {
            KEM::X25519 => kem_params::X25519_NENC,
            KEM::P256 => kem_params::P256_NENC,
            KEM::P384 => kem_params::P384_NENC,
            KEM::P521 => kem_params::P521_NENC,
            KEM::MLKEM768 => kem_params::MLKEM768_NENC,
            KEM::MLKEM1024 => kem_params::MLKEM1024_NENC,
        }
    }

    fn check_public_key(
        &self,
        py: pyo3::Python<'_>,
        key: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<()> {
        match self {
            KEM::X25519 => {
                if !key.is_instance(&types::X25519_PUBLIC_KEY.get(py)?)? {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyTypeError::new_err(
                            "Expected X25519PublicKey for KEM.X25519",
                        ),
                    ));
                }
            }
            KEM::P256 => Self::check_ec_public_key(
                py,
                key,
                &types::SECP256R1.get(py)?,
                "KEM.P256",
                "secp256r1",
            )?,
            KEM::P384 => Self::check_ec_public_key(
                py,
                key,
                &types::SECP384R1.get(py)?,
                "KEM.P384",
                "secp384r1",
            )?,
            KEM::P521 => Self::check_ec_public_key(
                py,
                key,
                &types::SECP521R1.get(py)?,
                "KEM.P521",
                "secp521r1",
            )?,
            KEM::MLKEM768 => {
                if !key.is_instance(&types::MLKEM768_PUBLIC_KEY.get(py)?)? {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyTypeError::new_err(
                            "Expected MLKEM768PublicKey for KEM.MLKEM768",
                        ),
                    ));
                }
            }
            KEM::MLKEM1024 => {
                if !key.is_instance(&types::MLKEM1024_PUBLIC_KEY.get(py)?)? {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyTypeError::new_err(
                            "Expected MLKEM1024PublicKey for KEM.MLKEM1024",
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn check_private_key(
        &self,
        py: pyo3::Python<'_>,
        key: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<()> {
        match self {
            KEM::X25519 => {
                if !key.is_instance(&types::X25519_PRIVATE_KEY.get(py)?)? {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyTypeError::new_err(
                            "Expected X25519PrivateKey for KEM.X25519",
                        ),
                    ));
                }
            }
            KEM::P256 => Self::check_ec_private_key(
                py,
                key,
                &types::SECP256R1.get(py)?,
                "KEM.P256",
                "secp256r1",
            )?,
            KEM::P384 => Self::check_ec_private_key(
                py,
                key,
                &types::SECP384R1.get(py)?,
                "KEM.P384",
                "secp384r1",
            )?,
            KEM::P521 => Self::check_ec_private_key(
                py,
                key,
                &types::SECP521R1.get(py)?,
                "KEM.P521",
                "secp521r1",
            )?,
            KEM::MLKEM768 => {
                if !key.is_instance(&types::MLKEM768_PRIVATE_KEY.get(py)?)? {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyTypeError::new_err(
                            "Expected MLKEM768PrivateKey for KEM.MLKEM768",
                        ),
                    ));
                }
            }
            KEM::MLKEM1024 => {
                if !key.is_instance(&types::MLKEM1024_PRIVATE_KEY.get(py)?)? {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyTypeError::new_err(
                            "Expected MLKEM1024PrivateKey for KEM.MLKEM1024",
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn encap<'p>(
        &self,
        py: pyo3::Python<'p>,
        pk_r: &pyo3::Bound<'p, pyo3::PyAny>,
        kem_suite_id: &[u8; 5],
    ) -> CryptographyResult<(
        pyo3::Bound<'p, pyo3::types::PyBytes>,
        pyo3::Bound<'p, pyo3::types::PyBytes>,
    )> {
        match self {
            KEM::MLKEM768 | KEM::MLKEM1024 => {
                let result = pk_r.call_method0(pyo3::intern!(py, "encapsulate"))?;
                Ok(result.extract()?)
            }
            KEM::X25519 | KEM::P256 | KEM::P384 | KEM::P521 => {
                self.dhkem_encap(py, pk_r, kem_suite_id)
            }
        }
    }

    fn decap<'p>(
        &self,
        py: pyo3::Python<'p>,
        enc: &[u8],
        sk_r: &pyo3::Bound<'p, pyo3::PyAny>,
        kem_suite_id: &[u8; 5],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        match self {
            KEM::MLKEM768 | KEM::MLKEM1024 => {
                let enc_bytes = pyo3::types::PyBytes::new(py, enc);
                Ok(sk_r
                    .call_method1(pyo3::intern!(py, "decapsulate"), (enc_bytes,))?
                    .extract()?)
            }
            KEM::X25519 | KEM::P256 | KEM::P384 | KEM::P521 => {
                self.dhkem_decap(py, enc, sk_r, kem_suite_id)
            }
        }
    }

    fn dhkem_encap<'p>(
        &self,
        py: pyo3::Python<'p>,
        pk_r: &pyo3::Bound<'p, pyo3::PyAny>,
        kem_suite_id: &[u8; 5],
    ) -> CryptographyResult<(
        pyo3::Bound<'p, pyo3::types::PyBytes>,
        pyo3::Bound<'p, pyo3::types::PyBytes>,
    )> {
        let sk_e = self.generate_key(py)?;
        let pk_e = sk_e.call_method0(pyo3::intern!(py, "public_key"))?;
        let pk_e_bytes = self.serialize_public_key(py, &pk_e)?;
        let pk_r_bytes = self.serialize_public_key(py, pk_r)?;

        let dh_result = self.exchange(py, &sk_e, pk_r)?;
        let dh = dh_result.extract::<&[u8]>()?;

        let mut kem_context =
            Vec::with_capacity(pk_e_bytes.as_bytes().len() + pk_r_bytes.as_bytes().len());
        kem_context.extend_from_slice(pk_e_bytes.as_bytes());
        kem_context.extend_from_slice(pk_r_bytes.as_bytes());

        let shared_secret = self.extract_and_expand(py, dh, &kem_context, kem_suite_id)?;
        Ok((shared_secret, pk_e_bytes))
    }

    fn dhkem_decap<'p>(
        &self,
        py: pyo3::Python<'p>,
        enc: &[u8],
        sk_r: &pyo3::Bound<'p, pyo3::PyAny>,
        kem_suite_id: &[u8; 5],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let pk_e = self.deserialize_public_key(py, enc)?;

        let dh_result = self.exchange(py, sk_r, &pk_e)?;
        let dh = dh_result.extract::<&[u8]>()?;

        let pk_rm = sk_r.call_method0(pyo3::intern!(py, "public_key"))?;
        let pk_rm_bytes = self.serialize_public_key(py, &pk_rm)?;

        let mut kem_context = Vec::with_capacity(enc.len() + pk_rm_bytes.as_bytes().len());
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(pk_rm_bytes.as_bytes());

        self.extract_and_expand(py, dh, &kem_context, kem_suite_id)
    }

    fn extract_and_expand<'p>(
        &self,
        py: pyo3::Python<'p>,
        dh: &[u8],
        kem_context: &[u8],
        kem_suite_id: &[u8; 5],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let eae_prk = self.kem_labeled_extract(py, b"eae_prk", dh, kem_suite_id)?;
        self.kem_labeled_expand(
            py,
            &eae_prk,
            b"shared_secret",
            kem_context,
            self.secret_length(),
            kem_suite_id,
        )
    }

    fn kem_labeled_extract(
        &self,
        py: pyo3::Python<'_>,
        label: &[u8],
        ikm: &[u8],
        kem_suite_id: &[u8; 5],
    ) -> CryptographyResult<cryptography_openssl::hmac::DigestBytes> {
        let mut labeled_ikm = Vec::with_capacity(HPKE_VERSION.len() + 5 + label.len() + ikm.len());
        labeled_ikm.extend_from_slice(HPKE_VERSION);
        labeled_ikm.extend_from_slice(kem_suite_id);
        labeled_ikm.extend_from_slice(label);
        labeled_ikm.extend_from_slice(ikm);

        let algorithm = self.kem_hash_algorithm(py)?;
        let buf = CffiBuf::from_bytes(py, &labeled_ikm);
        hkdf_extract(py, &algorithm.unbind(), None, &buf)
    }

    fn kem_labeled_expand<'p>(
        &self,
        py: pyo3::Python<'p>,
        prk: &[u8],
        label: &[u8],
        info: &[u8],
        length: usize,
        kem_suite_id: &[u8; 5],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut labeled_info =
            Vec::with_capacity(2 + HPKE_VERSION.len() + 5 + label.len() + info.len());
        labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
        labeled_info.extend_from_slice(HPKE_VERSION);
        labeled_info.extend_from_slice(kem_suite_id);
        labeled_info.extend_from_slice(label);
        labeled_info.extend_from_slice(info);

        let algorithm = self.kem_hash_algorithm(py)?;
        Suite::hkdf_expand(py, algorithm, prk, &labeled_info, length)
    }

    fn generate_key<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match self {
            KEM::X25519 => Ok(pyo3::Bound::new(py, x25519::generate_key()?)?.into_any()),
            KEM::P256 => {
                let secp256r1 = types::SECP256R1.get(py)?.call0()?;
                Ok(
                    pyo3::Bound::new(py, ec::generate_private_key(py, secp256r1, None)?)?
                        .into_any(),
                )
            }
            KEM::P384 => {
                let secp384r1 = types::SECP384R1.get(py)?.call0()?;
                Ok(
                    pyo3::Bound::new(py, ec::generate_private_key(py, secp384r1, None)?)?
                        .into_any(),
                )
            }
            KEM::P521 => {
                let secp521r1 = types::SECP521R1.get(py)?.call0()?;
                Ok(
                    pyo3::Bound::new(py, ec::generate_private_key(py, secp521r1, None)?)?
                        .into_any(),
                )
            }
            KEM::MLKEM768 | KEM::MLKEM1024 => {
                unreachable!("ML-KEM does not generate an ephemeral DH key")
            }
        }
    }

    fn serialize_public_key<'p>(
        &self,
        py: pyo3::Python<'p>,
        pk: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        match self {
            KEM::X25519 => Ok(pk
                .call_method0(pyo3::intern!(py, "public_bytes_raw"))?
                .extract()?),
            KEM::P256 | KEM::P384 | KEM::P521 => Ok(pk
                .call_method1(
                    pyo3::intern!(py, "public_bytes"),
                    (
                        crate::serialization::Encoding::X962,
                        crate::serialization::PublicFormat::UncompressedPoint,
                    ),
                )?
                .extract()?),
            KEM::MLKEM768 | KEM::MLKEM1024 => {
                unreachable!("ML-KEM public keys are not serialized via this path")
            }
        }
    }

    fn deserialize_public_key<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: &[u8],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match self {
            KEM::X25519 => Ok(pyo3::Bound::new(py, x25519::from_public_bytes(data)?)?.into_any()),
            KEM::P256 => {
                let secp256r1 = types::SECP256R1.get(py)?.call0()?;
                Ok(pyo3::Bound::new(py, ec::from_public_bytes(py, secp256r1, data)?)?.into_any())
            }
            KEM::P384 => {
                let secp384r1 = types::SECP384R1.get(py)?.call0()?;
                Ok(pyo3::Bound::new(py, ec::from_public_bytes(py, secp384r1, data)?)?.into_any())
            }
            KEM::P521 => {
                let secp521r1 = types::SECP521R1.get(py)?.call0()?;
                Ok(pyo3::Bound::new(py, ec::from_public_bytes(py, secp521r1, data)?)?.into_any())
            }
            KEM::MLKEM768 | KEM::MLKEM1024 => {
                unreachable!("ML-KEM encapsulated key is a ciphertext, not a public key")
            }
        }
    }

    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        private_key: &pyo3::Bound<'p, pyo3::PyAny>,
        public_key: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match self {
            KEM::X25519 => {
                Ok(private_key.call_method1(pyo3::intern!(py, "exchange"), (public_key,))?)
            }
            KEM::P256 | KEM::P384 | KEM::P521 => {
                let ecdh = types::ECDH.get(py)?.call0()?;
                Ok(private_key.call_method1(pyo3::intern!(py, "exchange"), (&ecdh, public_key))?)
            }
            KEM::MLKEM768 | KEM::MLKEM1024 => {
                unreachable!("ML-KEM does not perform a Diffie-Hellman exchange")
            }
        }
    }

    fn kem_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match self {
            KEM::X25519 | KEM::P256 => Ok(types::SHA256.get(py)?.call0()?),
            KEM::P384 => Ok(types::SHA384.get(py)?.call0()?),
            KEM::P521 => Ok(types::SHA512.get(py)?.call0()?),
            KEM::MLKEM768 | KEM::MLKEM1024 => {
                unreachable!("ML-KEM does not use a KEM hash algorithm")
            }
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[allow(non_camel_case_types)]
#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    from_py_object,
    module = "cryptography.hazmat.bindings._rust.openssl.hpke"
)]
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum KDF {
    HKDF_SHA256,
    HKDF_SHA384,
    HKDF_SHA512,
    SHAKE128,
    SHAKE256,
}

impl KDF {
    fn id(&self) -> u16 {
        match self {
            KDF::HKDF_SHA256 => kdf_params::HKDF_SHA256_ID,
            KDF::HKDF_SHA384 => kdf_params::HKDF_SHA384_ID,
            KDF::HKDF_SHA512 => kdf_params::HKDF_SHA512_ID,
            KDF::SHAKE128 => kdf_params::SHAKE128_ID,
            KDF::SHAKE256 => kdf_params::SHAKE256_ID,
        }
    }

    fn hash_output_length(&self) -> usize {
        match self {
            KDF::HKDF_SHA256 | KDF::HKDF_SHA384 | KDF::HKDF_SHA512 => {
                unreachable!("hash_output_length only used for one-stage KDFs")
            }
            KDF::SHAKE128 => kdf_params::SHAKE128_HASH_OUTPUT_LENGTH,
            KDF::SHAKE256 => kdf_params::SHAKE256_HASH_OUTPUT_LENGTH,
        }
    }

    fn is_one_stage(&self) -> bool {
        matches!(self, KDF::SHAKE128 | KDF::SHAKE256)
    }

    fn hkdf_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match self {
            KDF::HKDF_SHA256 => Ok(types::SHA256.get(py)?.call0()?),
            KDF::HKDF_SHA384 => Ok(types::SHA384.get(py)?.call0()?),
            KDF::HKDF_SHA512 => Ok(types::SHA512.get(py)?.call0()?),
            KDF::SHAKE128 => unreachable!("SHAKE128 is a one-stage KDF"),
            KDF::SHAKE256 => unreachable!("SHAKE256 is a one-stage KDF"),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[allow(non_camel_case_types)]
#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    from_py_object,
    module = "cryptography.hazmat.bindings._rust.openssl.hpke"
)]
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum AEAD {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
}

impl AEAD {
    fn id(&self) -> u16 {
        match self {
            AEAD::AES_128_GCM => aead_params::AES_128_GCM_ID,
            AEAD::AES_256_GCM => aead_params::AES_256_GCM_ID,
            AEAD::CHACHA20_POLY1305 => aead_params::CHACHA20_POLY1305_ID,
        }
    }

    fn key_length(&self) -> usize {
        match self {
            AEAD::AES_128_GCM => aead_params::AES_128_GCM_NK,
            AEAD::AES_256_GCM => aead_params::AES_256_GCM_NK,
            AEAD::CHACHA20_POLY1305 => aead_params::CHACHA20_POLY1305_NK,
        }
    }

    fn nonce_length(&self) -> usize {
        match self {
            AEAD::AES_128_GCM => aead_params::AES_128_GCM_NN,
            AEAD::AES_256_GCM => aead_params::AES_256_GCM_NN,
            AEAD::CHACHA20_POLY1305 => aead_params::CHACHA20_POLY1305_NN,
        }
    }

    fn tag_length(&self) -> usize {
        match self {
            AEAD::AES_128_GCM => aead_params::AES_128_GCM_NT,
            AEAD::AES_256_GCM => aead_params::AES_256_GCM_NT,
            AEAD::CHACHA20_POLY1305 => aead_params::CHACHA20_POLY1305_NT,
        }
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.hpke")]
pub(crate) struct Suite {
    aead: AEAD,
    kem: KEM,
    kem_suite_id: [u8; 5],
    hpke_suite_id: [u8; 10],
    kdf: KDF,
}

impl Suite {
    fn hkdf_expand<'p>(
        py: pyo3::Python<'p>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
        prk: &[u8],
        info: &[u8],
        length: usize,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut hkdf_expand = HkdfExpand::new(
            py,
            algorithm.unbind(),
            length,
            Some(pyo3::types::PyBytes::new(py, info).unbind()),
            None,
        )?;
        hkdf_expand.derive(py, CffiBuf::from_bytes(py, prk))
    }

    fn hpke_labeled_extract(
        &self,
        py: pyo3::Python<'_>,
        salt: Option<&[u8]>,
        label: &[u8],
        ikm: &[u8],
    ) -> CryptographyResult<cryptography_openssl::hmac::DigestBytes> {
        let mut labeled_ikm = Vec::with_capacity(HPKE_VERSION.len() + 10 + label.len() + ikm.len());
        labeled_ikm.extend_from_slice(HPKE_VERSION);
        labeled_ikm.extend_from_slice(&self.hpke_suite_id);
        labeled_ikm.extend_from_slice(label);
        labeled_ikm.extend_from_slice(ikm);

        let algorithm = self.kdf.hkdf_hash_algorithm(py)?;
        let buf = CffiBuf::from_bytes(py, &labeled_ikm);
        hkdf_extract(py, &algorithm.unbind(), salt, &buf)
    }

    fn hpke_labeled_expand<'p>(
        &self,
        py: pyo3::Python<'p>,
        prk: &[u8],
        label: &[u8],
        info: &[u8],
        length: usize,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut labeled_info =
            Vec::with_capacity(2 + HPKE_VERSION.len() + 10 + label.len() + info.len());
        labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
        labeled_info.extend_from_slice(HPKE_VERSION);
        labeled_info.extend_from_slice(&self.hpke_suite_id);
        labeled_info.extend_from_slice(label);
        labeled_info.extend_from_slice(info);
        let algorithm = self.kdf.hkdf_hash_algorithm(py)?;
        Suite::hkdf_expand(py, algorithm, prk, &labeled_info, length)
    }

    fn hpke_labeled_derive<'p>(
        &self,
        py: pyo3::Python<'p>,
        ikm: &[u8],
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let label_len = u16_length_prefix(label.len(), "label")?;
        let algorithm = match &self.kdf {
            KDF::HKDF_SHA256 | KDF::HKDF_SHA384 | KDF::HKDF_SHA512 => {
                unreachable!("hpke_labeled_derive only used for one-stage KDFs")
            }
            KDF::SHAKE128 => types::SHAKE128.get(py)?.call1((length,))?,
            KDF::SHAKE256 => types::SHAKE256.get(py)?.call1((length,))?,
        };
        let mut hash = Hash::new(py, &algorithm, None)?;
        hash.update_bytes(ikm)?;
        hash.update_bytes(HPKE_VERSION)?;
        hash.update_bytes(&self.hpke_suite_id)?;
        hash.update_bytes(&label_len)?;
        hash.update_bytes(label)?;
        hash.update_bytes(&(length as u16).to_be_bytes())?;
        hash.update_bytes(context)?;
        hash.finalize(py)
    }

    fn aead_encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        key: &pyo3::Bound<'_, pyo3::types::PyBytes>,
        nonce: &pyo3::Bound<'_, pyo3::types::PyBytes>,
        plaintext: CffiBuf<'_>,
        aad: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let key_obj = key.clone().unbind().into_any();
        let nonce_buf = CffiBuf::from_bytes(py, nonce.as_bytes());
        match &self.aead {
            AEAD::AES_128_GCM | AEAD::AES_256_GCM => {
                let cipher = AesGcm::new(py, key_obj)?;
                cipher.encrypt(py, nonce_buf, plaintext, aad)
            }
            AEAD::CHACHA20_POLY1305 => {
                let cipher = ChaCha20Poly1305::new(py, key_obj)?;
                cipher.encrypt(py, nonce_buf, plaintext, aad)
            }
        }
    }

    fn aead_decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        key: &pyo3::Bound<'_, pyo3::types::PyBytes>,
        nonce: &pyo3::Bound<'_, pyo3::types::PyBytes>,
        ciphertext: &[u8],
        aad: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let key_obj = key.clone().unbind().into_any();
        let nonce_buf = CffiBuf::from_bytes(py, nonce.as_bytes());
        match &self.aead {
            AEAD::AES_128_GCM | AEAD::AES_256_GCM => {
                let cipher = AesGcm::new(py, key_obj)?;
                cipher.decrypt(py, nonce_buf, CffiBuf::from_bytes(py, ciphertext), aad)
            }
            AEAD::CHACHA20_POLY1305 => {
                let cipher = ChaCha20Poly1305::new(py, key_obj)?;
                cipher.decrypt(py, nonce_buf, CffiBuf::from_bytes(py, ciphertext), aad)
            }
        }
    }

    fn encrypt_inner<'p>(
        &self,
        py: pyo3::Python<'p>,
        plaintext: CffiBuf<'_>,
        public_key: &pyo3::Bound<'p, pyo3::PyAny>,
        info: Option<CffiBuf<'_>>,
        aad: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.kem.check_public_key(py, public_key)?;
        let info_bytes: &[u8] = info.as_ref().map(|b| b.as_bytes()).unwrap_or(b"");

        let (shared_secret, enc) = self.kem.encap(py, public_key, &self.kem_suite_id)?;
        let (key, base_nonce) = self.key_schedule(py, shared_secret.as_bytes(), info_bytes)?;

        let ct = self.aead_encrypt(py, &key, &base_nonce, plaintext, aad)?;

        let enc_bytes = enc.as_bytes();
        let ct_bytes = ct.as_bytes();
        Ok(pyo3::types::PyBytes::new_with(
            py,
            enc_bytes.len() + ct_bytes.len(),
            |buf| {
                buf[..enc_bytes.len()].copy_from_slice(enc_bytes);
                buf[enc_bytes.len()..].copy_from_slice(ct_bytes);
                Ok(())
            },
        )?)
    }

    fn decrypt_inner<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: CffiBuf<'_>,
        private_key: &pyo3::Bound<'p, pyo3::PyAny>,
        info: Option<CffiBuf<'_>>,
        aad: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.kem.check_private_key(py, private_key)?;
        let ct_bytes = ciphertext.as_bytes();
        if ct_bytes.len() < self.kem.enc_length() + self.aead.tag_length() {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let info_bytes: &[u8] = info.as_ref().map(|b| b.as_bytes()).unwrap_or(b"");

        let (enc, ct) = ct_bytes.split_at(self.kem.enc_length());

        let shared_secret = self
            .kem
            .decap(py, enc, private_key, &self.kem_suite_id)
            .map_err(|_| CryptographyError::from(exceptions::InvalidTag::new_err(())))?;
        let (key, base_nonce) = self.key_schedule(py, shared_secret.as_bytes(), info_bytes)?;

        self.aead_decrypt(py, &key, &base_nonce, ct, aad)
    }

    fn key_schedule<'p>(
        &self,
        py: pyo3::Python<'p>,
        shared_secret: &[u8],
        info: &[u8],
    ) -> CryptographyResult<(
        pyo3::Bound<'p, pyo3::types::PyBytes>,
        pyo3::Bound<'p, pyo3::types::PyBytes>,
    )> {
        if self.kdf.is_one_stage() {
            let shared_secret_len = u16_length_prefix(shared_secret.len(), "shared_secret")?;
            let info_len = u16_length_prefix(info.len(), "info")?;

            let mut secrets = Vec::with_capacity(4 + shared_secret.len());
            secrets.extend_from_slice(&0u16.to_be_bytes());
            secrets.extend_from_slice(&shared_secret_len);
            secrets.extend_from_slice(shared_secret);

            let mut key_schedule_context = Vec::with_capacity(5 + info.len());
            key_schedule_context.push(HPKE_MODE_BASE);
            key_schedule_context.extend_from_slice(&0u16.to_be_bytes());
            key_schedule_context.extend_from_slice(&info_len);
            key_schedule_context.extend_from_slice(info);

            let key_length = self.aead.key_length();
            let nonce_length = self.aead.nonce_length();
            let secret = self.hpke_labeled_derive(
                py,
                &secrets,
                b"secret",
                &key_schedule_context,
                key_length + nonce_length + self.kdf.hash_output_length(),
            )?;
            let secret_bytes = secret.as_bytes();
            let key = pyo3::types::PyBytes::new(py, &secret_bytes[..key_length]);
            let base_nonce =
                pyo3::types::PyBytes::new(py, &secret_bytes[key_length..key_length + nonce_length]);

            return Ok((key, base_nonce));
        }

        let psk_id_hash = self.hpke_labeled_extract(py, None, b"psk_id_hash", b"")?;
        let info_hash = self.hpke_labeled_extract(py, None, b"info_hash", info)?;
        let mut key_schedule_context = vec![HPKE_MODE_BASE];
        key_schedule_context.extend_from_slice(&psk_id_hash);
        key_schedule_context.extend_from_slice(&info_hash);

        let secret = self.hpke_labeled_extract(py, Some(shared_secret), b"secret", b"")?;

        let key = self.hpke_labeled_expand(
            py,
            &secret,
            b"key",
            &key_schedule_context,
            self.aead.key_length(),
        )?;
        let base_nonce = self.hpke_labeled_expand(
            py,
            &secret,
            b"base_nonce",
            &key_schedule_context,
            self.aead.nonce_length(),
        )?;

        Ok((key, base_nonce))
    }
}

#[pyo3::pymethods]
impl Suite {
    #[new]
    fn new(kem: KEM, kdf: KDF, aead: AEAD) -> CryptographyResult<Suite> {
        // Build suite IDs
        let mut kem_suite_id = [0u8; 5];
        kem_suite_id[..3].copy_from_slice(b"KEM");
        kem_suite_id[3..].copy_from_slice(&kem.id().to_be_bytes());

        let mut hpke_suite_id = [0u8; 10];
        hpke_suite_id[..4].copy_from_slice(b"HPKE");
        hpke_suite_id[4..6].copy_from_slice(&kem.id().to_be_bytes());
        hpke_suite_id[6..8].copy_from_slice(&kdf.id().to_be_bytes());
        hpke_suite_id[8..10].copy_from_slice(&aead.id().to_be_bytes());

        Ok(Suite {
            aead,
            kem,
            kem_suite_id,
            hpke_suite_id,
            kdf,
        })
    }

    #[pyo3(signature = (plaintext, public_key, info=None))]
    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        plaintext: CffiBuf<'_>,
        public_key: &pyo3::Bound<'p, pyo3::PyAny>,
        info: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.encrypt_inner(py, plaintext, public_key, info, None)
    }

    #[pyo3(signature = (ciphertext, private_key, info=None))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: CffiBuf<'_>,
        private_key: &pyo3::Bound<'p, pyo3::PyAny>,
        info: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.decrypt_inner(py, ciphertext, private_key, info, None)
    }
}

#[pyo3::pyfunction]
#[pyo3(signature = (suite, plaintext, public_key, info=None, aad=None))]
fn _encrypt_with_aad<'p>(
    py: pyo3::Python<'p>,
    suite: &Suite,
    plaintext: CffiBuf<'_>,
    public_key: &pyo3::Bound<'p, pyo3::PyAny>,
    info: Option<CffiBuf<'_>>,
    aad: Option<CffiBuf<'_>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    suite.encrypt_inner(py, plaintext, public_key, info, aad)
}

#[pyo3::pyfunction]
#[pyo3(signature = (suite, ciphertext, private_key, info=None, aad=None))]
fn _decrypt_with_aad<'p>(
    py: pyo3::Python<'p>,
    suite: &Suite,
    ciphertext: CffiBuf<'_>,
    private_key: &pyo3::Bound<'p, pyo3::PyAny>,
    info: Option<CffiBuf<'_>>,
    aad: Option<CffiBuf<'_>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    suite.decrypt_inner(py, ciphertext, private_key, info, aad)
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod hpke {
    // stable and nightly rustfmt disagree on import ordering
    #[rustfmt::skip]
    #[pymodule_export]
    use super::{_decrypt_with_aad, _encrypt_with_aad, Suite, AEAD, KDF, KEM};
}

#[cfg(test)]
mod tests {
    use super::{kdf_params, kem_params};
    use super::{KDF, KEM};

    #[test]
    fn test_mlkem768_secret_length() {
        assert_eq!(KEM::MLKEM768.secret_length(), kem_params::MLKEM768_NSECRET);
    }

    #[test]
    fn test_mlkem1024_secret_length() {
        assert_eq!(
            KEM::MLKEM1024.secret_length(),
            kem_params::MLKEM1024_NSECRET
        );
    }

    #[test]
    #[should_panic(expected = "ML-KEM does not generate an ephemeral DH key")]
    fn test_mlkem768_generate_key_unreachable() {
        pyo3::Python::initialize();

        pyo3::Python::attach(|py| {
            let _ = KEM::MLKEM768.generate_key(py);
        });
    }

    #[test]
    #[should_panic(expected = "ML-KEM public keys are not serialized via this path")]
    fn test_mlkem768_serialize_public_key_unreachable() {
        pyo3::Python::initialize();

        pyo3::Python::attach(|py| {
            let obj = py.None().into_bound(py);
            let _ = KEM::MLKEM768.serialize_public_key(py, &obj);
        });
    }

    #[test]
    #[should_panic(expected = "ML-KEM encapsulated key is a ciphertext, not a public key")]
    fn test_mlkem768_deserialize_public_key_unreachable() {
        pyo3::Python::initialize();

        pyo3::Python::attach(|py| {
            let _ = KEM::MLKEM768.deserialize_public_key(py, b"");
        });
    }

    #[test]
    #[should_panic(expected = "ML-KEM does not perform a Diffie-Hellman exchange")]
    fn test_mlkem768_exchange_unreachable() {
        pyo3::Python::initialize();

        pyo3::Python::attach(|py| {
            let obj = py.None().into_bound(py);
            let _ = KEM::MLKEM768.exchange(py, &obj, &obj);
        });
    }

    #[test]
    #[should_panic(expected = "ML-KEM does not use a KEM hash algorithm")]
    fn test_mlkem768_kem_hash_algorithm_unreachable() {
        pyo3::Python::initialize();

        pyo3::Python::attach(|py| {
            let _ = KEM::MLKEM768.kem_hash_algorithm(py);
        });
    }

    #[test]
    #[should_panic(expected = "SHAKE128 is a one-stage KDF")]
    fn test_shake128_hkdf_hash_algorithm_unreachable() {
        pyo3::Python::initialize();

        pyo3::Python::attach(|py| {
            let _ = KDF::SHAKE128.hkdf_hash_algorithm(py);
        });
    }

    #[test]
    #[should_panic(expected = "SHAKE256 is a one-stage KDF")]
    fn test_shake256_hkdf_hash_algorithm_unreachable() {
        pyo3::Python::initialize();

        pyo3::Python::attach(|py| {
            let _ = KDF::SHAKE256.hkdf_hash_algorithm(py);
        });
    }

    #[test]
    fn test_shake256_kdf_params() {
        assert_eq!(KDF::SHAKE256.id(), kdf_params::SHAKE256_ID);
        assert!(KDF::SHAKE256.is_one_stage());
        assert_eq!(KDF::SHAKE256.hash_output_length(), 64);
    }

    #[test]
    #[should_panic(expected = "hash_output_length only used for one-stage KDFs")]
    fn test_hkdf_hash_output_length_unreachable() {
        let _ = KDF::HKDF_SHA256.hash_output_length();
    }

    #[test]
    #[should_panic(expected = "hpke_labeled_derive only used for one-stage KDFs")]
    fn test_hpke_labeled_derive_unreachable_hkdf() {
        pyo3::Python::initialize();

        pyo3::Python::attach(|py| {
            let suite = super::Suite {
                aead: super::AEAD::AES_128_GCM,
                kem: super::KEM::X25519,
                kem_suite_id: [0u8; 5],
                hpke_suite_id: [0u8; 10],
                kdf: KDF::HKDF_SHA256,
            };
            let _ = suite.hpke_labeled_derive(py, b"", b"test", b"", 32);
        });
    }
}
