// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

// Implementation of the Fernet specification
// (https://github.com/fernet/spec/blob/master/Spec.md).

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE};
use base64::engine::{DecodePaddingMode, Engine};
use cryptography_crypto::constant_time;
use openssl_bridge::cipher::Direction as Mode;
use pyo3::types::{PyAnyMethods, PyBytesMethods, PyStringMethods};

use crate::backend::run_with_gil_detached;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::types;

pyo3::import_exception!(cryptography.fernet, InvalidToken);

const VERSION: u8 = 0x80;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const BLOCK_LEN: usize = 16;
const HMAC_LEN: usize = 32;
// A token is: version (1 byte) || timestamp (8 bytes) || IV (16 bytes) ||
// ciphertext || HMAC (32 bytes).
const HEADER_LEN: usize = 1 + 8 + IV_LEN;
const MAX_CLOCK_SKEW: i64 = 60;

fn invalid_token() -> CryptographyError {
    CryptographyError::from(InvalidToken::new_err(()))
}

// Padding is optional when decoding.
const URL_SAFE_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn b64encode<'p>(
    py: pyo3::Python<'p>,
    data: &[u8],
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let len = base64::encoded_len(data.len(), true).expect("data too long");
    Ok(pyo3::types::PyBytes::new_with(py, len, |out| {
        URL_SAFE
            .encode_slice(data, out)
            .expect("output buffer is sized exactly");
        Ok(())
    })?)
}

/// Checks that a token created at `timestamp` is not older than `ttl` seconds
/// and not from the future (beyond the allowed clock skew) at `current_time`.
fn is_valid_at(timestamp: u64, ttl: i64, current_time: i64) -> bool {
    let (ts, ttl, now, skew) = (
        i128::from(timestamp),
        i128::from(ttl),
        i128::from(current_time),
        i128::from(MAX_CLOCK_SKEW),
    );
    !(ts + ttl < now || now + skew < ts)
}

/// Returns `int(time.time())`. This goes through Python so that patching
/// `time.time` (as test suites commonly do) is honored.
fn current_time(py: pyo3::Python<'_>) -> CryptographyResult<i64> {
    let now = types::TIME
        .get(py)?
        .getattr(pyo3::intern!(py, "time"))?
        .call0()?
        .extract::<f64>()?;
    Ok(now as i64)
}

/// Parses a token into its timestamp and decoded contents, without verifying
/// the signature.
fn unverified_token_data(
    token: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<(u64, Vec<u8>)> {
    let data = if let Ok(s) = token.cast::<pyo3::types::PyString>() {
        URL_SAFE_LENIENT.decode(s.to_cow()?.as_bytes()).ok()
    } else if let Ok(b) = token.cast::<pyo3::types::PyBytes>() {
        URL_SAFE_LENIENT.decode(b.as_bytes()).ok()
    } else {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err("token must be bytes or str"),
        ));
    };
    let data = data.ok_or_else(invalid_token)?;
    if data.len() < 9 || data[0] != VERSION {
        return Err(invalid_token());
    }
    let timestamp = u64::from_be_bytes(data[1..9].try_into().unwrap());
    Ok((timestamp, data))
}

#[pyo3::pyclass(frozen, subclass, module = "cryptography.hazmat.bindings._rust.fernet")]
pub(crate) struct Fernet {
    // Keyed contexts that every operation starts from a copy of. Keying a
    // context is much more expensive than copying one.
    hmac: openssl_bridge::mac::Hmac,
    cipher: openssl_bridge::cipher::CipherKey,
}

impl Fernet {
    fn from_key(key: &[u8]) -> openssl_bridge::Result<Fernet> {
        let (signing_key, encryption_key) = key.split_at(KEY_LEN / 2);
        let hmac = openssl_bridge::mac::Hmac::new(
            openssl_bridge::hash::Algorithm::from_name("sha256")?,
            signing_key,
        )?;
        let cipher = openssl_bridge::cipher::CipherKey::new(
            openssl_bridge::cipher::Cipher::Aes128Cbc,
            encryption_key,
            true,
        )?;
        Ok(Fernet { hmac, cipher })
    }

    fn hmac(&self, data: &[u8]) -> openssl_bridge::Result<Vec<u8>> {
        let mut h = self.hmac.try_clone()?;
        h.update(data)?;
        h.finish()
    }

    /// AES-128-CBC with PKCS7 padding. `output` must have room for
    /// `input.len() + BLOCK_LEN` bytes. Returns the number of bytes written.
    fn aes_cbc(
        &self,
        mode: Mode,
        iv: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> openssl_bridge::Result<usize> {
        let mut ctx = self.cipher.start(mode, iv)?;
        let n = ctx.update_into(input, output)?;
        let tail: openssl_bridge::secret::SecretBytes = ctx.finish()?.into();
        output[n..n + tail.as_ref().len()].copy_from_slice(tail.as_ref());
        Ok(n + tail.as_ref().len())
    }

    /// Builds the raw (not yet base64-encoded) token.
    fn encrypt_from_parts(
        &self,
        py: pyo3::Python<'_>,
        data: &[u8],
        timestamp: u64,
        iv: &[u8],
    ) -> CryptographyResult<Vec<u8>> {
        run_with_gil_detached(py, data.len(), || {
            // PKCS7 padding always adds at least one byte.
            let ciphertext_len = (data.len() / BLOCK_LEN + 1) * BLOCK_LEN;
            let body_len = HEADER_LEN + ciphertext_len;
            let mut token = vec![0u8; body_len + HMAC_LEN];
            token[0] = VERSION;
            token[1..9].copy_from_slice(&timestamp.to_be_bytes());
            token[9..HEADER_LEN].copy_from_slice(iv);
            // The cipher needs room for one extra block beyond the input; the
            // not-yet-written HMAC region provides that slack.
            let n = self.aes_cbc(Mode::Encrypt, iv, data, &mut token[HEADER_LEN..])?;
            debug_assert_eq!(n, ciphertext_len);
            let hmac = self.hmac(&token[..body_len])?;
            token[body_len..].copy_from_slice(&hmac);
            Ok(token)
        })
    }

    fn verify_signature(&self, data: &[u8]) -> CryptographyResult<()> {
        let (body, tag) = data.split_at(data.len().saturating_sub(HMAC_LEN));
        if !constant_time::bytes_eq(&self.hmac(body)?, tag) {
            return Err(invalid_token());
        }
        Ok(())
    }

    fn decrypt_data(
        &self,
        py: pyo3::Python<'_>,
        data: &[u8],
        timestamp: u64,
        time_info: Option<(i64, i64)>,
    ) -> CryptographyResult<Vec<u8>> {
        if let Some((ttl, current_time)) = time_info {
            if !is_valid_at(timestamp, ttl, current_time) {
                return Err(invalid_token());
            }
        }

        run_with_gil_detached(py, data.len(), || {
            self.verify_signature(data)?;
            // A verified token is at least HMAC_LEN bytes long.
            let body = &data[..data.len() - HMAC_LEN];
            let iv = &data[9..HEADER_LEN];
            let ciphertext = body.get(HEADER_LEN..).unwrap_or(&[]);
            let mut plaintext = vec![0u8; ciphertext.len() + BLOCK_LEN];
            // The signature is valid, so the only way the cipher can fail is
            // bad padding.
            let n = self
                .aes_cbc(Mode::Decrypt, iv, ciphertext, &mut plaintext)
                .map_err(|_| invalid_token())?;
            plaintext.truncate(n);
            Ok(plaintext)
        })
    }

    fn decrypt_token<'p>(
        &self,
        py: pyo3::Python<'p>,
        token: &pyo3::Bound<'_, pyo3::PyAny>,
        time_info: Option<(i64, i64)>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let (timestamp, data) = unverified_token_data(token)?;
        let plaintext = self.decrypt_data(py, &data, timestamp, time_info)?;
        Ok(pyo3::types::PyBytes::new(py, &plaintext))
    }
}

#[pyo3::pymethods]
impl Fernet {
    #[new]
    #[pyo3(signature = (key, backend=None))]
    fn new(
        key: &pyo3::Bound<'_, pyo3::PyAny>,
        backend: Option<&pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<Fernet> {
        let _ = backend;
        let invalid_key = || {
            CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                "Fernet key must be 32 url-safe base64-encoded bytes.",
            ))
        };
        let key = if let Ok(s) = key.cast::<pyo3::types::PyString>() {
            URL_SAFE_LENIENT.decode(s.to_cow()?.as_bytes()).ok()
        } else {
            URL_SAFE_LENIENT
                .decode(key.extract::<CffiBuf<'_>>()?.as_bytes())
                .ok()
        };
        let key = key.ok_or_else(invalid_key)?;
        if key.len() != KEY_LEN {
            return Err(invalid_key());
        }
        Ok(Fernet::from_key(&key)?)
    }

    #[classmethod]
    fn generate_key<'p>(
        cls: &pyo3::Bound<'p, pyo3::types::PyType>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut key = [0u8; KEY_LEN];
        openssl_bridge::rand::fill_private(&mut key)?;
        b64encode(cls.py(), &key)
    }

    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.encrypt_at_time(py, data, current_time(py)?.try_into().unwrap())
    }

    fn encrypt_at_time<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        current_time: u64,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut iv = [0u8; IV_LEN];
        openssl_bridge::rand::fill_private(&mut iv)?;
        let token = self.encrypt_from_parts(py, data.as_bytes(), current_time, &iv)?;
        b64encode(py, &token)
    }

    fn _encrypt_from_parts<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        current_time: u64,
        iv: [u8; IV_LEN],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let token = self.encrypt_from_parts(py, data.as_bytes(), current_time, &iv)?;
        b64encode(py, &token)
    }

    #[pyo3(signature = (token, ttl=None))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        token: &pyo3::Bound<'_, pyo3::PyAny>,
        ttl: Option<i64>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let time_info = match ttl {
            Some(ttl) => Some((ttl, current_time(py)?)),
            None => None,
        };
        self.decrypt_token(py, token, time_info)
    }

    fn decrypt_at_time<'p>(
        &self,
        py: pyo3::Python<'p>,
        token: &pyo3::Bound<'_, pyo3::PyAny>,
        ttl: Option<i64>,
        current_time: i64,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let Some(ttl) = ttl else {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "decrypt_at_time() can only be used with a non-None ttl",
                ),
            ));
        };
        self.decrypt_token(py, token, Some((ttl, current_time)))
    }

    fn extract_timestamp(&self, token: &pyo3::Bound<'_, pyo3::PyAny>) -> CryptographyResult<u64> {
        let (timestamp, data) = unverified_token_data(token)?;
        // Verify the token was not tampered with.
        self.verify_signature(&data)?;
        Ok(timestamp)
    }

    #[staticmethod]
    fn _get_unverified_token_data<'p>(
        py: pyo3::Python<'p>,
        token: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<(u64, pyo3::Bound<'p, pyo3::types::PyBytes>)> {
        let (timestamp, data) = unverified_token_data(token)?;
        Ok((timestamp, pyo3::types::PyBytes::new(py, &data)))
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.fernet")]
pub(crate) struct MultiFernet {
    fernets: Vec<pyo3::Py<Fernet>>,
}

impl MultiFernet {
    fn decrypt_token<'p>(
        &self,
        py: pyo3::Python<'p>,
        token: &pyo3::Bound<'_, pyo3::PyAny>,
        time_info: Option<(i64, i64)>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        // Parse the token once rather than once per key.
        let (timestamp, data) = unverified_token_data(token)?;
        for f in &self.fernets {
            if let Ok(plaintext) = f.get().decrypt_data(py, &data, timestamp, time_info) {
                return Ok(pyo3::types::PyBytes::new(py, &plaintext));
            }
        }
        Err(invalid_token())
    }
}

#[pyo3::pymethods]
impl MultiFernet {
    #[new]
    fn new(fernets: Vec<pyo3::Py<Fernet>>) -> CryptographyResult<MultiFernet> {
        if fernets.is_empty() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "MultiFernet requires at least one Fernet instance",
                ),
            ));
        }
        Ok(MultiFernet { fernets })
    }

    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        msg: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.fernets[0].get().encrypt(py, msg)
    }

    fn encrypt_at_time<'p>(
        &self,
        py: pyo3::Python<'p>,
        msg: CffiBuf<'_>,
        current_time: u64,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.fernets[0].get().encrypt_at_time(py, msg, current_time)
    }

    fn rotate<'p>(
        &self,
        py: pyo3::Python<'p>,
        msg: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let (timestamp, data) = unverified_token_data(msg)?;
        let plaintext = self
            .fernets
            .iter()
            .find_map(|f| f.get().decrypt_data(py, &data, timestamp, None).ok())
            .ok_or_else(invalid_token)?;

        let mut iv = [0u8; IV_LEN];
        openssl_bridge::rand::fill_private(&mut iv)?;
        let token = self.fernets[0]
            .get()
            .encrypt_from_parts(py, &plaintext, timestamp, &iv)?;
        b64encode(py, &token)
    }

    #[pyo3(signature = (msg, ttl=None))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        msg: &pyo3::Bound<'_, pyo3::PyAny>,
        ttl: Option<i64>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let time_info = match ttl {
            Some(ttl) => Some((ttl, current_time(py)?)),
            None => None,
        };
        self.decrypt_token(py, msg, time_info)
    }

    fn decrypt_at_time<'p>(
        &self,
        py: pyo3::Python<'p>,
        msg: &pyo3::Bound<'_, pyo3::PyAny>,
        ttl: Option<i64>,
        current_time: i64,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let Some(ttl) = ttl else {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "decrypt_at_time() can only be used with a non-None ttl",
                ),
            ));
        };
        self.decrypt_token(py, msg, Some((ttl, current_time)))
    }

    fn extract_timestamp(&self, msg: &pyo3::Bound<'_, pyo3::PyAny>) -> CryptographyResult<u64> {
        // Parse the token once rather than once per key.
        let (timestamp, data) = unverified_token_data(msg)?;
        for f in &self.fernets {
            if f.get().verify_signature(&data).is_ok() {
                return Ok(timestamp);
            }
        }
        Err(invalid_token())
    }
}

#[pyo3::pymodule(gil_used = false)]
#[pyo3(name = "fernet")]
pub(crate) mod fernet_mod {
    #[pymodule_export]
    use super::{Fernet, MultiFernet};
}
