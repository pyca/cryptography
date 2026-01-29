// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::aead::EvpCipherAead;
use crate::backend::hmac::Hmac;
use crate::backend::kdf::hkdf_extract;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;
use pyo3::types::{PyAnyMethods, PyBytesMethods};

const HPKE_VERSION: &[u8] = b"HPKE-v1";
const HPKE_MODE_BASE: u8 = 0x00;

// Algorithm parameters organized by type for easy extension
mod kem_params {
    pub const X25519_ID: u16 = 0x0020;
    pub const X25519_NSECRET: usize = 32;
    pub const X25519_NENC: usize = 32;
}

mod kdf_params {
    pub const HKDF_SHA256_ID: u16 = 0x0001;
}

mod aead_params {
    pub const AES_128_GCM_ID: u16 = 0x0001;
    pub const AES_128_GCM_NK: usize = 16;
    pub const AES_128_GCM_NN: usize = 12;
    pub const AES_128_GCM_NT: usize = 16;
}

#[allow(clippy::upper_case_acronyms)]
#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    module = "cryptography.hazmat.bindings._rust.openssl.hpke"
)]
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum KEM {
    X25519,
}

#[allow(clippy::upper_case_acronyms)]
#[allow(non_camel_case_types)]
#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    module = "cryptography.hazmat.bindings._rust.openssl.hpke"
)]
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum KDF {
    HKDF_SHA256,
}

#[allow(clippy::upper_case_acronyms)]
#[allow(non_camel_case_types)]
#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    module = "cryptography.hazmat.bindings._rust.openssl.hpke"
)]
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum AEAD {
    AES_128_GCM,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.hpke")]
pub(crate) struct Suite {
    kem_suite_id: [u8; 5],
    hpke_suite_id: [u8; 10],
}

impl Suite {
    fn hkdf_expand(
        &self,
        py: pyo3::Python<'_>,
        prk: &[u8],
        info: &[u8],
        length: usize,
    ) -> CryptographyResult<Vec<u8>> {
        let algorithm = crate::types::SHA256.get(py)?.call0()?;
        let digest_size = algorithm
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;

        let h_prime = Hmac::new_bytes(py, prk, &algorithm)?;

        let mut output = vec![0u8; length];
        let mut pos = 0usize;
        let mut counter = 0u8;

        while pos < length {
            counter += 1;
            let mut h = h_prime.copy(py)?;

            let start = pos.saturating_sub(digest_size);
            h.update_bytes(&output[start..pos])?;
            h.update_bytes(info)?;
            h.update_bytes(&[counter])?;

            let block = h.finalize(py)?;
            let block_bytes = block.as_bytes();

            let copy_len = (length - pos).min(digest_size);
            output[pos..pos + copy_len].copy_from_slice(&block_bytes[..copy_len]);
            pos += copy_len;
        }

        Ok(output)
    }

    fn kem_labeled_extract(
        &self,
        py: pyo3::Python<'_>,
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> CryptographyResult<cryptography_openssl::hmac::DigestBytes> {
        let mut labeled_ikm = Vec::with_capacity(HPKE_VERSION.len() + 5 + label.len() + ikm.len());
        labeled_ikm.extend_from_slice(HPKE_VERSION);
        labeled_ikm.extend_from_slice(&self.kem_suite_id);
        labeled_ikm.extend_from_slice(label);
        labeled_ikm.extend_from_slice(ikm);

        let algorithm = crate::types::SHA256.get(py)?.call0()?;
        let buf = CffiBuf::from_bytes(py, &labeled_ikm);
        let salt_py = if salt.is_empty() {
            None
        } else {
            Some(pyo3::types::PyBytes::new(py, salt).unbind())
        };
        hkdf_extract(py, &algorithm.unbind(), salt_py.as_ref(), &buf)
    }

    fn kem_labeled_expand(
        &self,
        py: pyo3::Python<'_>,
        prk: &[u8],
        label: &[u8],
        info: &[u8],
        length: usize,
    ) -> CryptographyResult<Vec<u8>> {
        let mut labeled_info =
            Vec::with_capacity(2 + HPKE_VERSION.len() + 5 + label.len() + info.len());
        labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
        labeled_info.extend_from_slice(HPKE_VERSION);
        labeled_info.extend_from_slice(&self.kem_suite_id);
        labeled_info.extend_from_slice(label);
        labeled_info.extend_from_slice(info);
        self.hkdf_expand(py, prk, &labeled_info, length)
    }

    fn extract_and_expand(
        &self,
        py: pyo3::Python<'_>,
        dh: &[u8],
        kem_context: &[u8],
    ) -> CryptographyResult<Vec<u8>> {
        let eae_prk = self.kem_labeled_extract(py, b"", b"eae_prk", dh)?;
        self.kem_labeled_expand(
            py,
            &eae_prk,
            b"shared_secret",
            kem_context,
            kem_params::X25519_NSECRET,
        )
    }

    fn encap(
        &self,
        py: pyo3::Python<'_>,
        pk_r: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<(Vec<u8>, Vec<u8>)> {
        // Generate ephemeral key pair using x25519 module
        let x25519_mod = py.import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.x25519"
        ))?;
        let sk_e = x25519_mod
            .getattr(pyo3::intern!(py, "X25519PrivateKey"))?
            .call_method0(pyo3::intern!(py, "generate"))?;
        let pk_e = sk_e.call_method0(pyo3::intern!(py, "public_key"))?;

        // Get ephemeral public key raw bytes
        let pk_e_bytes = pk_e.call_method0(pyo3::intern!(py, "public_bytes_raw"))?;
        let pk_e_raw = pk_e_bytes.extract::<&[u8]>()?;

        // Get recipient's public key raw bytes
        let pk_r_bytes = pk_r.call_method0(pyo3::intern!(py, "public_bytes_raw"))?;
        let pk_r_raw = pk_r_bytes.extract::<&[u8]>()?;

        // Perform ECDH via Python API
        let dh_result = sk_e.call_method1(pyo3::intern!(py, "exchange"), (pk_r,))?;
        let dh = dh_result.extract::<&[u8]>()?;

        let mut kem_context = [0u8; 64];
        kem_context[..32].copy_from_slice(pk_e_raw);
        kem_context[32..].copy_from_slice(pk_r_raw);
        let shared_secret = self.extract_and_expand(py, dh, &kem_context)?;
        Ok((shared_secret, pk_e_raw.to_vec()))
    }

    fn decap(
        &self,
        py: pyo3::Python<'_>,
        enc: &[u8],
        sk_r: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<Vec<u8>> {
        // Reconstruct pk_e from enc via Python
        let x25519_mod = py.import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.x25519"
        ))?;
        let pk_e = x25519_mod
            .getattr(pyo3::intern!(py, "X25519PublicKey"))?
            .call_method1(pyo3::intern!(py, "from_public_bytes"), (enc,))
            .map_err(|_| {
                CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "Invalid encapsulated key",
                ))
            })?;

        // Perform ECDH via Python API
        let dh_result = sk_r.call_method1(pyo3::intern!(py, "exchange"), (&pk_e,))?;
        let dh = dh_result.extract::<&[u8]>()?;

        // Get our public key
        let pk_rm = sk_r.call_method0(pyo3::intern!(py, "public_key"))?;
        let pk_rm_bytes = pk_rm.call_method0(pyo3::intern!(py, "public_bytes_raw"))?;
        let pk_rm_raw = pk_rm_bytes.extract::<&[u8]>()?;

        let mut kem_context = [0u8; 64];
        kem_context[..32].copy_from_slice(enc);
        kem_context[32..].copy_from_slice(pk_rm_raw);
        self.extract_and_expand(py, dh, &kem_context)
    }

    fn hpke_labeled_extract(
        &self,
        py: pyo3::Python<'_>,
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> CryptographyResult<cryptography_openssl::hmac::DigestBytes> {
        let mut labeled_ikm = Vec::with_capacity(HPKE_VERSION.len() + 10 + label.len() + ikm.len());
        labeled_ikm.extend_from_slice(HPKE_VERSION);
        labeled_ikm.extend_from_slice(&self.hpke_suite_id);
        labeled_ikm.extend_from_slice(label);
        labeled_ikm.extend_from_slice(ikm);

        let algorithm = crate::types::SHA256.get(py)?.call0()?;
        let buf = CffiBuf::from_bytes(py, &labeled_ikm);
        let salt_py = if salt.is_empty() {
            None
        } else {
            Some(pyo3::types::PyBytes::new(py, salt).unbind())
        };
        hkdf_extract(py, &algorithm.unbind(), salt_py.as_ref(), &buf)
    }

    fn hpke_labeled_expand(
        &self,
        py: pyo3::Python<'_>,
        prk: &[u8],
        label: &[u8],
        info: &[u8],
        length: usize,
    ) -> CryptographyResult<Vec<u8>> {
        let mut labeled_info =
            Vec::with_capacity(2 + HPKE_VERSION.len() + 10 + label.len() + info.len());
        labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
        labeled_info.extend_from_slice(HPKE_VERSION);
        labeled_info.extend_from_slice(&self.hpke_suite_id);
        labeled_info.extend_from_slice(label);
        labeled_info.extend_from_slice(info);
        self.hkdf_expand(py, prk, &labeled_info, length)
    }

    fn key_schedule(
        &self,
        py: pyo3::Python<'_>,
        shared_secret: &[u8],
        info: &[u8],
    ) -> CryptographyResult<(
        [u8; aead_params::AES_128_GCM_NK],
        [u8; aead_params::AES_128_GCM_NN],
    )> {
        let psk_id_hash = self.hpke_labeled_extract(py, b"", b"psk_id_hash", b"")?;
        let info_hash = self.hpke_labeled_extract(py, b"", b"info_hash", info)?;
        let mut key_schedule_context = vec![HPKE_MODE_BASE];
        key_schedule_context.extend_from_slice(&psk_id_hash);
        key_schedule_context.extend_from_slice(&info_hash);

        let secret = self.hpke_labeled_extract(py, shared_secret, b"secret", b"")?;

        let key_vec = self.hpke_labeled_expand(
            py,
            &secret,
            b"key",
            &key_schedule_context,
            aead_params::AES_128_GCM_NK,
        )?;
        let nonce_vec = self.hpke_labeled_expand(
            py,
            &secret,
            b"base_nonce",
            &key_schedule_context,
            aead_params::AES_128_GCM_NN,
        )?;

        let mut key = [0u8; aead_params::AES_128_GCM_NK];
        let mut base_nonce = [0u8; aead_params::AES_128_GCM_NN];
        key.copy_from_slice(&key_vec);
        base_nonce.copy_from_slice(&nonce_vec);

        Ok((key, base_nonce))
    }
}

#[pyo3::pymethods]
impl Suite {
    #[new]
    fn new(_kem: KEM, _kdf: KDF, _aead: AEAD) -> CryptographyResult<Suite> {
        // Build suite IDs
        let mut kem_suite_id = [0u8; 5];
        kem_suite_id[..3].copy_from_slice(b"KEM");
        kem_suite_id[3..].copy_from_slice(&kem_params::X25519_ID.to_be_bytes());

        let mut hpke_suite_id = [0u8; 10];
        hpke_suite_id[..4].copy_from_slice(b"HPKE");
        hpke_suite_id[4..6].copy_from_slice(&kem_params::X25519_ID.to_be_bytes());
        hpke_suite_id[6..8].copy_from_slice(&kdf_params::HKDF_SHA256_ID.to_be_bytes());
        hpke_suite_id[8..10].copy_from_slice(&aead_params::AES_128_GCM_ID.to_be_bytes());

        Ok(Suite {
            kem_suite_id,
            hpke_suite_id,
        })
    }

    #[pyo3(signature = (plaintext, public_key, info=None, aad=None))]
    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        plaintext: CffiBuf<'_>,
        public_key: &pyo3::Bound<'_, pyo3::PyAny>,
        info: Option<CffiBuf<'_>>,
        aad: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let info_bytes: &[u8] = info.as_ref().map(|b| b.as_bytes()).unwrap_or(b"");
        let aad_bytes: &[u8] = aad.as_ref().map(|b| b.as_bytes()).unwrap_or(b"");

        let (shared_secret, enc) = self.encap(py, public_key)?;
        let (key, base_nonce) = self.key_schedule(py, &shared_secret, info_bytes)?;

        // Create AEAD with the derived key
        let cipher = openssl::cipher::Cipher::aes_128_gcm();
        let aead = EvpCipherAead::new(cipher, &key, aead_params::AES_128_GCM_NT, false)?;

        let pt_bytes = plaintext.as_bytes();
        let ct_len = pt_bytes.len() + aead_params::AES_128_GCM_NT;

        Ok(pyo3::types::PyBytes::new_with(
            py,
            enc.len() + ct_len,
            |buf| {
                buf[..enc.len()].copy_from_slice(&enc);
                let aad_opt = if aad_bytes.is_empty() {
                    None
                } else {
                    Some(crate::backend::aead::Aad::Single(CffiBuf::from_bytes(
                        py, aad_bytes,
                    )))
                };
                aead.encrypt_into(
                    py,
                    pt_bytes,
                    aad_opt,
                    Some(&base_nonce),
                    &mut buf[enc.len()..],
                )?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (ciphertext, private_key, info=None, aad=None))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: CffiBuf<'_>,
        private_key: &pyo3::Bound<'_, pyo3::PyAny>,
        info: Option<CffiBuf<'_>>,
        aad: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ct_bytes = ciphertext.as_bytes();
        if ct_bytes.len() < kem_params::X25519_NENC {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let info_bytes: &[u8] = info.as_ref().map(|b| b.as_bytes()).unwrap_or(b"");
        let aad_bytes: &[u8] = aad.as_ref().map(|b| b.as_bytes()).unwrap_or(b"");

        let (enc, ct) = ct_bytes.split_at(kem_params::X25519_NENC);

        let shared_secret = self.decap(py, enc, private_key)?;
        let (key, base_nonce) = self.key_schedule(py, &shared_secret, info_bytes)?;

        // Create AEAD with the derived key
        let cipher = openssl::cipher::Cipher::aes_128_gcm();
        let aead = EvpCipherAead::new(cipher, &key, aead_params::AES_128_GCM_NT, false)?;

        if ct.len() < aead_params::AES_128_GCM_NT {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }
        let pt_len = ct.len() - aead_params::AES_128_GCM_NT;

        Ok(pyo3::types::PyBytes::new_with(py, pt_len, |buf| {
            let aad_opt = if aad_bytes.is_empty() {
                None
            } else {
                Some(crate::backend::aead::Aad::Single(CffiBuf::from_bytes(
                    py, aad_bytes,
                )))
            };
            aead.decrypt_into(py, ct, aad_opt, Some(&base_nonce), buf)?;
            Ok(())
        })?)
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod hpke {
    #[pymodule_export]
    use super::{Suite, AEAD, KDF, KEM};
}
