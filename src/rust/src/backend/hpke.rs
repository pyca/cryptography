// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::hmac::Hmac;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;
use crate::types;
use pyo3::types::{PyAnyMethods, PyBytesMethods};

const HPKE_VERSION: &[u8] = b"HPKE-v1";
const HPKE_MODE_BASE: u8 = 0x00;

// KEM parameters for X25519 (DHKEM(X25519, HKDF-SHA256))
const KEM_ID: u16 = 0x0020;
const KEM_NSECRET: usize = 32;
const KEM_NENC: usize = 32;

// KDF parameters for HKDF-SHA256
const KDF_ID: u16 = 0x0001;

// AEAD parameters for AES-128-GCM
const AEAD_ID: u16 = 0x0001;
const AEAD_NK: usize = 16;
const AEAD_NN: usize = 12;
const AEAD_NT: usize = 16;

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

#[pyo3::pymethods]
impl KEM {}

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

#[pyo3::pymethods]
impl KDF {}

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

#[pyo3::pymethods]
impl AEAD {}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.hpke")]
pub(crate) struct Suite {
    kem_suite_id: [u8; 5],
    hpke_suite_id: [u8; 10],
}

impl Suite {
    fn hkdf_extract(
        &self,
        py: pyo3::Python<'_>,
        salt: &[u8],
        ikm: &[u8],
    ) -> CryptographyResult<cryptography_openssl::hmac::DigestBytes> {
        let sha256 = types::SHA256.get(py)?.call0()?;
        let digest_size = sha256
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;
        let default_salt = vec![0u8; digest_size];
        let salt_bytes = if salt.is_empty() { &default_salt } else { salt };
        let mut hmac = Hmac::new_bytes(py, salt_bytes, &sha256)?;
        hmac.update_bytes(ikm)?;
        hmac.finalize_bytes()
    }

    fn hkdf_expand(
        &self,
        py: pyo3::Python<'_>,
        prk: &[u8],
        info: &[u8],
        length: usize,
    ) -> CryptographyResult<Vec<u8>> {
        let sha256 = types::SHA256.get(py)?.call0()?;
        let digest_size = sha256
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;

        let h_prime = Hmac::new_bytes(py, prk, &sha256)?;

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
        self.hkdf_extract(py, salt, &labeled_ikm)
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
        self.kem_labeled_expand(py, &eae_prk, b"shared_secret", kem_context, KEM_NSECRET)
    }

    fn encap(
        &self,
        py: pyo3::Python<'_>,
        pk_r: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<(Vec<u8>, Vec<u8>)> {
        // Generate ephemeral key pair using OpenSSL directly
        let sk_e_pkey = openssl::pkey::PKey::generate_x25519()?;
        let pk_e_raw = sk_e_pkey.raw_public_key()?;

        // Get recipient's public key raw bytes via Python API
        let pk_r_bytes = pk_r.call_method0(pyo3::intern!(py, "public_bytes_raw"))?;
        let pk_r_raw = pk_r_bytes.extract::<&[u8]>()?;

        // Create recipient public key from raw bytes
        let pk_r_pkey =
            openssl::pkey::PKey::public_key_from_raw_bytes(pk_r_raw, openssl::pkey::Id::X25519)?;

        // Perform ECDH
        let mut deriver = openssl::derive::Deriver::new(&sk_e_pkey)?;
        deriver.set_peer(&pk_r_pkey)?;
        let mut dh = vec![0u8; deriver.len()?];
        let n = deriver.derive(&mut dh)?;
        assert_eq!(n, dh.len());

        let mut kem_context = [0u8; 64];
        kem_context[..32].copy_from_slice(&pk_e_raw);
        kem_context[32..].copy_from_slice(pk_r_raw);
        let shared_secret = self.extract_and_expand(py, &dh, &kem_context)?;
        Ok((shared_secret, pk_e_raw))
    }

    fn decap(
        &self,
        py: pyo3::Python<'_>,
        enc: &[u8],
        sk_r: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<Vec<u8>> {
        // Reconstruct pk_e from enc
        let pk_e_pkey =
            openssl::pkey::PKey::public_key_from_raw_bytes(enc, openssl::pkey::Id::X25519)
                .map_err(|_| {
                    CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                        "Invalid encapsulated key",
                    ))
                })?;

        // Get our private key raw bytes via Python API
        let sk_r_bytes = sk_r.call_method0(pyo3::intern!(py, "private_bytes_raw"))?;
        let sk_r_raw = sk_r_bytes.extract::<&[u8]>()?;

        // Reconstruct private key from raw bytes
        let sk_r_pkey =
            openssl::pkey::PKey::private_key_from_raw_bytes(sk_r_raw, openssl::pkey::Id::X25519)?;

        // Perform ECDH
        let mut deriver = openssl::derive::Deriver::new(&sk_r_pkey)?;
        deriver.set_peer(&pk_e_pkey)?;
        let mut dh = vec![0u8; deriver.len()?];
        let n = deriver.derive(&mut dh)?;
        assert_eq!(n, dh.len());

        // Get our public key
        let pk_rm = sk_r_pkey.raw_public_key()?;

        let mut kem_context = [0u8; 64];
        kem_context[..32].copy_from_slice(enc);
        kem_context[32..].copy_from_slice(&pk_rm);
        self.extract_and_expand(py, &dh, &kem_context)
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
        self.hkdf_extract(py, salt, &labeled_ikm)
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
    ) -> CryptographyResult<([u8; AEAD_NK], [u8; AEAD_NN])> {
        let psk_id_hash = self.hpke_labeled_extract(py, b"", b"psk_id_hash", b"")?;
        let info_hash = self.hpke_labeled_extract(py, b"", b"info_hash", info)?;
        let mut key_schedule_context = vec![HPKE_MODE_BASE];
        key_schedule_context.extend_from_slice(&psk_id_hash);
        key_schedule_context.extend_from_slice(&info_hash);

        let secret = self.hpke_labeled_extract(py, shared_secret, b"secret", b"")?;

        let key_vec =
            self.hpke_labeled_expand(py, &secret, b"key", &key_schedule_context, AEAD_NK)?;
        let nonce_vec =
            self.hpke_labeled_expand(py, &secret, b"base_nonce", &key_schedule_context, AEAD_NN)?;

        let mut key = [0u8; AEAD_NK];
        let mut base_nonce = [0u8; AEAD_NN];
        key.copy_from_slice(&key_vec);
        base_nonce.copy_from_slice(&nonce_vec);

        Ok((key, base_nonce))
    }

    fn aead_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> CryptographyResult<Vec<u8>> {
        let cipher = openssl::cipher::Cipher::aes_128_gcm();

        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
        ctx.encrypt_init(Some(cipher), Some(key), None)?;
        ctx.set_iv_length(nonce.len())?;
        ctx.encrypt_init(None, None, Some(nonce))?;

        // Process AAD
        if !aad.is_empty() {
            ctx.cipher_update(aad, None)?;
        }

        // Encrypt plaintext
        let mut ciphertext = vec![0u8; plaintext.len() + AEAD_NT];
        let n = ctx.cipher_update(plaintext, Some(&mut ciphertext[..plaintext.len()]))?;
        assert_eq!(n, plaintext.len());

        let mut final_block = [0u8; 0];
        let n = ctx.cipher_final(&mut final_block)?;
        assert_eq!(n, 0);

        // Get tag
        ctx.tag(&mut ciphertext[plaintext.len()..])
            .map_err(CryptographyError::from)?;

        Ok(ciphertext)
    }

    fn aead_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> CryptographyResult<Vec<u8>> {
        if ciphertext.len() < AEAD_NT {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let cipher = openssl::cipher::Cipher::aes_128_gcm();

        let ct_len = ciphertext.len() - AEAD_NT;
        let (ct_data, tag) = ciphertext.split_at(ct_len);

        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
        ctx.decrypt_init(Some(cipher), Some(key), None)?;
        ctx.set_iv_length(nonce.len())?;
        ctx.decrypt_init(None, None, Some(nonce))?;
        ctx.set_tag(tag)?;

        // Process AAD
        if !aad.is_empty() {
            ctx.cipher_update(aad, None)?;
        }

        // Decrypt ciphertext
        let mut plaintext = vec![0u8; ct_len];
        let n = ctx
            .cipher_update(ct_data, Some(&mut plaintext))
            .map_err(|_| exceptions::InvalidTag::new_err(()))?;
        assert_eq!(n, ct_len);

        ctx.cipher_final(&mut [])
            .map_err(|_| exceptions::InvalidTag::new_err(()))?;

        Ok(plaintext)
    }
}

#[pyo3::pymethods]
impl Suite {
    #[new]
    fn new(_kem: KEM, _kdf: KDF, _aead: AEAD) -> CryptographyResult<Suite> {
        // Build suite IDs
        let mut kem_suite_id = [0u8; 5];
        kem_suite_id[..3].copy_from_slice(b"KEM");
        kem_suite_id[3..].copy_from_slice(&KEM_ID.to_be_bytes());

        let mut hpke_suite_id = [0u8; 10];
        hpke_suite_id[..4].copy_from_slice(b"HPKE");
        hpke_suite_id[4..6].copy_from_slice(&KEM_ID.to_be_bytes());
        hpke_suite_id[6..8].copy_from_slice(&KDF_ID.to_be_bytes());
        hpke_suite_id[8..10].copy_from_slice(&AEAD_ID.to_be_bytes());

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
        let ct = self.aead_encrypt(&key, &base_nonce, plaintext.as_bytes(), aad_bytes)?;

        // Combine enc + ct
        Ok(pyo3::types::PyBytes::new_with(
            py,
            enc.len() + ct.len(),
            |buf| {
                buf[..enc.len()].copy_from_slice(&enc);
                buf[enc.len()..].copy_from_slice(&ct);
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
        if ct_bytes.len() < KEM_NENC {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let info_bytes: &[u8] = info.as_ref().map(|b| b.as_bytes()).unwrap_or(b"");
        let aad_bytes: &[u8] = aad.as_ref().map(|b| b.as_bytes()).unwrap_or(b"");

        let (enc, ct) = ct_bytes.split_at(KEM_NENC);

        let shared_secret = self.decap(py, enc, private_key)?;
        let (key, base_nonce) = self.key_schedule(py, &shared_secret, info_bytes)?;
        let plaintext = self.aead_decrypt(&key, &base_nonce, ct, aad_bytes)?;

        Ok(pyo3::types::PyBytes::new(py, &plaintext))
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod hpke {
    #[pymodule_export]
    use super::{Suite, AEAD, KDF, KEM};
}
