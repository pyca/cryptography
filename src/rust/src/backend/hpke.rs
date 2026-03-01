// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::{PyAnyMethods, PyBytesMethods};

use crate::backend::aead::{AesGcm, ChaCha20Poly1305};
use crate::backend::kdf::{hkdf_extract, HkdfExpand};
use crate::backend::x25519;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

const HPKE_VERSION: &[u8] = b"HPKE-v1";
const HPKE_MODE_BASE: u8 = 0x00;

mod kem_params {
    pub const X25519_ID: u16 = 0x0020;
    pub const X25519_NSECRET: usize = 32;
    pub const X25519_NENC: usize = 32;
}

mod kdf_params {
    pub const HKDF_SHA256_ID: u16 = 0x0001;
    pub const HKDF_SHA512_ID: u16 = 0x0003;
}

mod aead_params {
    pub const AES_128_GCM_ID: u16 = 0x0001;
    pub const AES_128_GCM_NK: usize = 16;
    pub const AES_128_GCM_NN: usize = 12;
    pub const AES_128_GCM_NT: usize = 16;

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
    HKDF_SHA512,
}

impl KDF {
    fn id(&self) -> u16 {
        match self {
            KDF::HKDF_SHA256 => kdf_params::HKDF_SHA256_ID,
            KDF::HKDF_SHA512 => kdf_params::HKDF_SHA512_ID,
        }
    }

    fn hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match self {
            KDF::HKDF_SHA256 => Ok(types::SHA256.get(py)?.call0()?),
            KDF::HKDF_SHA512 => Ok(types::SHA512.get(py)?.call0()?),
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
    CHACHA20_POLY1305,
}

impl AEAD {
    fn id(&self) -> u16 {
        match self {
            AEAD::AES_128_GCM => aead_params::AES_128_GCM_ID,
            AEAD::CHACHA20_POLY1305 => aead_params::CHACHA20_POLY1305_ID,
        }
    }

    fn key_length(&self) -> usize {
        match self {
            AEAD::AES_128_GCM => aead_params::AES_128_GCM_NK,
            AEAD::CHACHA20_POLY1305 => aead_params::CHACHA20_POLY1305_NK,
        }
    }

    fn nonce_length(&self) -> usize {
        match self {
            AEAD::AES_128_GCM => aead_params::AES_128_GCM_NN,
            AEAD::CHACHA20_POLY1305 => aead_params::CHACHA20_POLY1305_NN,
        }
    }

    fn tag_length(&self) -> usize {
        match self {
            AEAD::AES_128_GCM => aead_params::AES_128_GCM_NT,
            AEAD::CHACHA20_POLY1305 => aead_params::CHACHA20_POLY1305_NT,
        }
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.hpke")]
pub(crate) struct Suite {
    aead: AEAD,
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

    fn kem_labeled_extract(
        &self,
        py: pyo3::Python<'_>,
        label: &[u8],
        ikm: &[u8],
    ) -> CryptographyResult<cryptography_openssl::hmac::DigestBytes> {
        let mut labeled_ikm = Vec::with_capacity(HPKE_VERSION.len() + 5 + label.len() + ikm.len());
        labeled_ikm.extend_from_slice(HPKE_VERSION);
        labeled_ikm.extend_from_slice(&self.kem_suite_id);
        labeled_ikm.extend_from_slice(label);
        labeled_ikm.extend_from_slice(ikm);

        let algorithm = types::SHA256.get(py)?.call0()?;
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
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut labeled_info =
            Vec::with_capacity(2 + HPKE_VERSION.len() + 5 + label.len() + info.len());
        labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
        labeled_info.extend_from_slice(HPKE_VERSION);
        labeled_info.extend_from_slice(&self.kem_suite_id);
        labeled_info.extend_from_slice(label);
        labeled_info.extend_from_slice(info);

        let algorithm = types::SHA256.get(py)?.call0()?;
        Suite::hkdf_expand(py, algorithm, prk, &labeled_info, length)
    }

    fn extract_and_expand<'p>(
        &self,
        py: pyo3::Python<'p>,
        dh: &[u8],
        kem_context: &[u8],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let eae_prk = self.kem_labeled_extract(py, b"eae_prk", dh)?;
        self.kem_labeled_expand(
            py,
            &eae_prk,
            b"shared_secret",
            kem_context,
            kem_params::X25519_NSECRET,
        )
    }

    fn encap<'p>(
        &self,
        py: pyo3::Python<'p>,
        pk_r: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<(
        pyo3::Bound<'p, pyo3::types::PyBytes>,
        pyo3::Bound<'p, pyo3::types::PyBytes>,
    )> {
        let sk_e = pyo3::Bound::new(py, x25519::generate_key()?)?;
        let pk_e = sk_e.call_method0(pyo3::intern!(py, "public_key"))?;

        let pk_e_bytes: pyo3::Bound<'p, pyo3::types::PyBytes> = pk_e
            .call_method0(pyo3::intern!(py, "public_bytes_raw"))?
            .extract()?;

        let pk_r_bytes = pk_r.call_method0(pyo3::intern!(py, "public_bytes_raw"))?;
        let pk_r_raw = pk_r_bytes.extract::<&[u8]>()?;

        let dh_result = sk_e.call_method1(pyo3::intern!(py, "exchange"), (pk_r,))?;
        let dh = dh_result.extract::<&[u8]>()?;

        let mut kem_context = [0u8; 64];
        kem_context[..32].copy_from_slice(pk_e_bytes.as_bytes());
        kem_context[32..].copy_from_slice(pk_r_raw);
        let shared_secret = self.extract_and_expand(py, dh, &kem_context)?;
        Ok((shared_secret, pk_e_bytes))
    }

    fn decap<'p>(
        &self,
        py: pyo3::Python<'p>,
        enc: &[u8],
        sk_r: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        // Reconstruct pk_e from enc
        let pk_e = pyo3::Bound::new(py, x25519::from_public_bytes(enc)?)?;

        let dh_result = sk_r.call_method1(pyo3::intern!(py, "exchange"), (&pk_e,))?;
        let dh = dh_result.extract::<&[u8]>()?;

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
        salt: Option<&[u8]>,
        label: &[u8],
        ikm: &[u8],
    ) -> CryptographyResult<cryptography_openssl::hmac::DigestBytes> {
        let mut labeled_ikm = Vec::with_capacity(HPKE_VERSION.len() + 10 + label.len() + ikm.len());
        labeled_ikm.extend_from_slice(HPKE_VERSION);
        labeled_ikm.extend_from_slice(&self.hpke_suite_id);
        labeled_ikm.extend_from_slice(label);
        labeled_ikm.extend_from_slice(ikm);

        let algorithm = self.kdf.hash_algorithm(py)?;
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
        let algorithm = self.kdf.hash_algorithm(py)?;
        Suite::hkdf_expand(py, algorithm, prk, &labeled_info, length)
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
            AEAD::AES_128_GCM => {
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
            AEAD::AES_128_GCM => {
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
        public_key: &pyo3::Bound<'_, pyo3::PyAny>,
        info: Option<CffiBuf<'_>>,
        aad: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let info_bytes: &[u8] = info.as_ref().map(|b| b.as_bytes()).unwrap_or(b"");

        let (shared_secret, enc) = self.encap(py, public_key)?;
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
        private_key: &pyo3::Bound<'_, pyo3::PyAny>,
        info: Option<CffiBuf<'_>>,
        aad: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ct_bytes = ciphertext.as_bytes();
        if ct_bytes.len() < kem_params::X25519_NENC + self.aead.tag_length() {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let info_bytes: &[u8] = info.as_ref().map(|b| b.as_bytes()).unwrap_or(b"");

        let (enc, ct) = ct_bytes.split_at(kem_params::X25519_NENC);

        let shared_secret = self
            .decap(py, enc, private_key)
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
    fn new(_kem: KEM, kdf: KDF, aead: AEAD) -> CryptographyResult<Suite> {
        // Build suite IDs
        let mut kem_suite_id = [0u8; 5];
        kem_suite_id[..3].copy_from_slice(b"KEM");
        kem_suite_id[3..].copy_from_slice(&kem_params::X25519_ID.to_be_bytes());

        let mut hpke_suite_id = [0u8; 10];
        hpke_suite_id[..4].copy_from_slice(b"HPKE");
        hpke_suite_id[4..6].copy_from_slice(&kem_params::X25519_ID.to_be_bytes());
        hpke_suite_id[6..8].copy_from_slice(&kdf.id().to_be_bytes());
        hpke_suite_id[8..10].copy_from_slice(&aead.id().to_be_bytes());

        Ok(Suite {
            aead,
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
        public_key: &pyo3::Bound<'_, pyo3::PyAny>,
        info: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.encrypt_inner(py, plaintext, public_key, info, None)
    }

    #[pyo3(signature = (ciphertext, private_key, info=None))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: CffiBuf<'_>,
        private_key: &pyo3::Bound<'_, pyo3::PyAny>,
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
    public_key: &pyo3::Bound<'_, pyo3::PyAny>,
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
    private_key: &pyo3::Bound<'_, pyo3::PyAny>,
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
