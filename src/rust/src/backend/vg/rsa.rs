// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! RSA keys on verified-garbage: PKCS #1 v1.5 and PSS signatures, PKCS #1
//! v1.5 and OAEP encryption, all by verified-garbage's verified padding
//! functions. Only the encodings that carry no secret (PKCS #1 v1.5
//! signatures without a `DigestInfo`, and recovering such a signature's
//! data) are built here, on verified-garbage's raw RSA operations.

use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use cryptography_crypto::hash::MessageDigest;
use cryptography_key_parsing::raw;
use pyo3::types::PyAnyMethods;
use verified_garbage::rsa as vg_rsa;
use verified_garbage::{rsa_keygen, rsa_oaep, rsa_pkcs1_enc, rsa_pkcs1_sig, rsa_pss};

use crate::backend::ec::trim_zeros;
use crate::backend::{hashes, utils};
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.rsa",
    name = "RSAPrivateKey"
)]
pub(crate) struct RsaPrivateKey {
    key: vg_rsa::PrivateKey,
    public: vg_rsa::PublicKey,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.rsa",
    name = "RSAPublicKey"
)]
pub(crate) struct RsaPublicKey {
    /// verified-garbage's key, or why it cannot hold this one (a size or
    /// exponent outside its limits, or an even modulus): such a key can be
    /// loaded, compared and serialized, but its operations are refused as
    /// unsupported.
    key: Result<vg_rsa::PublicKey, String>,
    /// The modulus and public exponent (verified-garbage's key does not
    /// expose them), without leading zeros.
    n: Vec<u8>,
    e: Vec<u8>,
}

/// Compares two unsigned big-endian integers.
fn cmp_be(a: &[u8], b: &[u8]) -> Ordering {
    let (a, b) = (trim_zeros(a), trim_zeros(b));
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// The bit length of an unsigned big-endian integer.
fn bit_length(n: &[u8]) -> usize {
    let n = trim_zeros(n);
    match n.first() {
        Some(&b) => 8 * n.len() - b.leading_zeros() as usize,
        None => 0,
    }
}

fn unsupported_key(msg: String) -> CryptographyError {
    CryptographyError::from(exceptions::UnsupportedAlgorithm::new_err((
        msg,
        exceptions::Reasons::UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
    )))
}

/// Why verified-garbage cannot hold a key: a modulus of fewer than 512 or
/// more than 8192 bits, or a public exponent of `2^33` or more (BoringSSL's
/// limits).
fn unsupported_reason(n: &[u8], e: &[u8]) -> Option<String> {
    let bits = bit_length(n);
    if !(8 * vg_rsa::MIN_MODULUS_LEN..=8 * vg_rsa::MAX_MODULUS_LEN).contains(&bits) {
        return Some(format!(
            "RSA keys with a {bits}-bit modulus are not supported by this backend (it supports 512 to 8192 bits)"
        ));
    }
    if bit_length(e) > 33 {
        return Some(
            "RSA public exponents of 2**33 or more are not supported by this backend".to_string(),
        );
    }
    None
}

/// Refuses, as unsupported, the keys verified-garbage cannot hold
/// (`unsupported_reason`).
fn check_supported(n: &[u8], e: &[u8]) -> CryptographyResult<()> {
    match unsupported_reason(n, e) {
        Some(reason) => Err(unsupported_key(reason)),
        None => Ok(()),
    }
}

/// The checks cryptography makes of every public key.
fn check_public_key_components(e: &[u8], n: &[u8]) -> CryptographyResult<()> {
    if cmp_be(n, &[3]).is_lt() {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("n must be >= 3."),
        ));
    }

    if cmp_be(e, &[3]).is_lt() || cmp_be(e, n).is_ge() {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("e must be >= 3 and < n."),
        ));
    }

    if e.last().is_none_or(|b| b & 1 == 0) {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("e must be odd."),
        ));
    }

    Ok(())
}

fn public_key_from_components(n: &[u8], e: &[u8]) -> CryptographyResult<RsaPublicKey> {
    check_public_key_components(e, n)?;
    let (n, e) = (trim_zeros(n), trim_zeros(e));
    let key = match unsupported_reason(n, e) {
        Some(reason) => Err(reason),
        // Within the supported sizes, verified-garbage refuses only an even
        // modulus.
        None => vg_rsa::PublicKey::new(n, e).map_err(|_| {
            "RSA keys with an even modulus are not supported by this backend".to_string()
        }),
    };
    Ok(RsaPublicKey {
        key,
        n: n.to_vec(),
        e: e.to_vec(),
    })
}

/// A private key from its CRT components. verified-garbage checks, as it
/// loads the key, that `p q = n`, `qInv < p`, `q qInv ≡ 1 (mod p)` and that
/// `dP` and `dQ` are `e`'s inverses modulo `p - 1` and `q - 1`; unless
/// `unsafe_skip_rsa_key_validation`, `RSA_check_key`'s checks of `d` too,
/// and that `p` and `q` are odd. (Skipping cannot skip the checks made at
/// loading: verified-garbage never holds a key that fails them.)
#[allow(clippy::too_many_arguments)]
fn private_key_from_components(
    n: &[u8],
    e: &[u8],
    d: &[u8],
    p: &[u8],
    q: &[u8],
    dmp1: &[u8],
    dmq1: &[u8],
    iqmp: &[u8],
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<RsaPrivateKey> {
    let invalid = || {
        CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
            "Invalid private key",
        ))
    };
    check_supported(n, e)?;
    let n = trim_zeros(n);
    let key =
        vg_rsa::PrivateKey::from_crt(n, e, d, p, q, dmp1, dmq1, iqmp).map_err(|_| invalid())?;
    if !unsafe_skip_rsa_key_validation
        && (!key.check_key()
            || p.last().is_none_or(|b| b & 1 == 0)
            || q.last().is_none_or(|b| b & 1 == 0))
    {
        return Err(invalid());
    }
    let public = vg_rsa::PublicKey::new(n, e).map_err(|_| invalid())?;
    Ok(RsaPrivateKey { key, public })
}

/// The key object of a parsed RSA (or RSA-PSS, whose restrictions are
/// dropped) private key.
pub(crate) fn private_key_from_raw(
    key: &raw::RsaPrivateKey,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<RsaPrivateKey> {
    private_key_from_components(
        &key.n,
        &key.e,
        &key.d,
        &key.p,
        &key.q,
        &key.dmp1,
        &key.dmq1,
        &key.iqmp,
        unsafe_skip_rsa_key_validation,
    )
}

/// The key object of a parsed RSA (or RSA-PSS) public key.
pub(crate) fn public_key_from_raw(key: &raw::RsaPublicKey) -> CryptographyResult<RsaPublicKey> {
    public_key_from_components(&key.n, &key.e)
}

#[pyo3::pyfunction]
fn generate_private_key(
    py: pyo3::Python<'_>,
    public_exponent: u32,
    key_size: u32,
) -> CryptographyResult<RsaPrivateKey> {
    let bits = key_size as usize;
    // verified-garbage rounds the size down to a multiple of 128 bits;
    // cryptography promises the size asked for.
    if bits % 128 != 0
        || !(rsa_keygen::MIN_MODULUS_BITS..=rsa_keygen::MAX_MODULUS_BITS).contains(&bits)
    {
        return Err(unsupported_key(format!(
            "Generating {bits}-bit RSA keys is not supported by this backend (the key size must be a multiple of 128 bits, at most 8192)"
        )));
    }
    let e = public_exponent.to_be_bytes();
    let key = py
        .detach(|| rsa_keygen::generate(bits, &e))
        .map_err(|_| CryptographyError::VerifiedGarbage("RSA key generation failed"))?;
    let [n, e, ..] = key.components();
    let public = vg_rsa::PublicKey::new(n, e)
        .map_err(|_| CryptographyError::VerifiedGarbage("RSA key generation failed"))?;
    Ok(RsaPrivateKey { key, public })
}

fn pkcs1_hash(md: MessageDigest) -> Option<rsa_pkcs1_sig::Hash> {
    use rsa_pkcs1_sig::Hash;
    Some(match md {
        MessageDigest::Md5 => Hash::Md5,
        MessageDigest::Sha1 => Hash::Sha1,
        MessageDigest::Sha224 => Hash::Sha224,
        MessageDigest::Sha256 => Hash::Sha256,
        MessageDigest::Sha384 => Hash::Sha384,
        MessageDigest::Sha512 => Hash::Sha512,
        MessageDigest::Sha512_224 => Hash::Sha512_224,
        MessageDigest::Sha512_256 => Hash::Sha512_256,
        MessageDigest::Sha3_224 => Hash::Sha3_224,
        MessageDigest::Sha3_256 => Hash::Sha3_256,
        MessageDigest::Sha3_384 => Hash::Sha3_384,
        MessageDigest::Sha3_512 => Hash::Sha3_512,
        _ => return None,
    })
}

fn pss_hash(md: MessageDigest) -> Option<rsa_pss::Hash> {
    use rsa_pss::Hash;
    Some(match md {
        MessageDigest::Md5 => Hash::Md5,
        MessageDigest::Sha1 => Hash::Sha1,
        MessageDigest::Sha224 => Hash::Sha224,
        MessageDigest::Sha256 => Hash::Sha256,
        MessageDigest::Sha384 => Hash::Sha384,
        MessageDigest::Sha512 => Hash::Sha512,
        MessageDigest::Sha512_224 => Hash::Sha512_224,
        MessageDigest::Sha512_256 => Hash::Sha512_256,
        _ => return None,
    })
}

/// Whether verified-garbage has OAEP with the hash function `hash` and
/// MGF1 over `mgf1`: the same function, or SHA-1, for SHA-1, SHA-224,
/// SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256.
fn oaep_pair(hash: MessageDigest, mgf1: MessageDigest) -> Option<(rsa_oaep::Hash, rsa_oaep::Hash)> {
    let supported = matches!(
        hash,
        MessageDigest::Sha1
            | MessageDigest::Sha224
            | MessageDigest::Sha256
            | MessageDigest::Sha384
            | MessageDigest::Sha512
            | MessageDigest::Sha512_224
            | MessageDigest::Sha512_256
    );
    if !supported || (mgf1 != hash && mgf1 != MessageDigest::Sha1) {
        return None;
    }
    Some((pkcs1_hash(hash)?, pkcs1_hash(mgf1)?))
}

enum PssSalt {
    Max,
    Digest,
    Auto,
    Len(usize),
}

enum SignatureScheme {
    /// PKCS #1 v1.5 with the `DigestInfo` of a hash value, or (`None`) of
    /// the data as it is (`NoDigestInfo`).
    Pkcs1(Option<rsa_pkcs1_sig::Hash>),
    Pss {
        hash: rsa_pss::Hash,
        salt: PssSalt,
    },
}

/// The scheme of a signature operation, with the errors (and their order)
/// of the OpenSSL backend's `setup_signature_ctx`.
fn signature_scheme(
    py: pyo3::Python<'_>,
    padding: &pyo3::Bound<'_, pyo3::PyAny>,
    algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    key_size: usize,
    is_signing: bool,
) -> CryptographyResult<SignatureScheme> {
    if !padding.is_instance(&types::ASYMMETRIC_PADDING.get(py)?)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "Padding must be an instance of AsymmetricPadding.",
            ),
        ));
    }

    let is_pss = if padding.is_instance(&types::PKCS1V15.get(py)?)? {
        false
    } else if padding.is_instance(&types::PSS.get(py)?)? {
        if !padding
            .getattr(pyo3::intern!(py, "_mgf"))?
            .is_instance(&types::MGF1.get(py)?)?
        {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Only MGF1 is supported.",
                    exceptions::Reasons::UNSUPPORTED_MGF,
                )),
            ));
        }

        // PSS padding requires a hash algorithm
        if !algorithm.is_instance(&types::HASH_ALGORITHM.get(py)?)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Expected instance of hashes.HashAlgorithm.",
                ),
            ));
        }

        if algorithm
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?
            + 2
            > key_size
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Digest too large for key size. Use a larger key or different digest.",
                ),
            ));
        }
        true
    } else {
        return Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err((
                format!(
                    "{} is not supported by this backend.",
                    padding.getattr(pyo3::intern!(py, "name"))?
                ),
                exceptions::Reasons::UNSUPPORTED_PADDING,
            )),
        ));
    };

    let unsupported_hash = |algorithm: &pyo3::Bound<'_, pyo3::PyAny>| {
        Ok::<_, CryptographyError>(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err((
                format!(
                    "{} is not supported by this backend for RSA signing.",
                    algorithm.getattr(pyo3::intern!(py, "name"))?
                ),
                exceptions::Reasons::UNSUPPORTED_HASH,
            )),
        ))
    };
    let md = if algorithm.is_none() {
        None
    } else {
        Some(hashes::message_digest_from_algorithm(py, algorithm)?)
    };

    if !is_pss {
        let hash = match md {
            None => None,
            Some(md) => match pkcs1_hash(md) {
                Some(hash) => Some(hash),
                None => return Err(unsupported_hash(algorithm)?),
            },
        };
        return Ok(SignatureScheme::Pkcs1(hash));
    }

    // `md` is set: PSS requires a hash algorithm, checked above.
    let Some(hash) = md.and_then(pss_hash) else {
        return Err(unsupported_hash(algorithm)?);
    };

    let salt = padding.getattr(pyo3::intern!(py, "_salt_length"))?;
    let salt = if salt.is_instance(&types::PADDING_MAX_LENGTH.get(py)?)? {
        PssSalt::Max
    } else if salt.is_instance(&types::PADDING_DIGEST_LENGTH.get(py)?)? {
        PssSalt::Digest
    } else if salt.is_instance(&types::PADDING_AUTO.get(py)?)? {
        if is_signing {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "PSS salt length can only be set to Auto when verifying",
                ),
            ));
        }
        PssSalt::Auto
    } else {
        PssSalt::Len(salt.extract::<usize>()?)
    };

    let mgf1_algorithm = padding
        .getattr(pyo3::intern!(py, "_mgf"))?
        .getattr(pyo3::intern!(py, "_algorithm"))?;
    let mgf1_md = hashes::message_digest_from_algorithm(py, &mgf1_algorithm)?;
    if pss_hash(mgf1_md) != Some(hash) {
        return Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err((
                "This backend supports PSS only with MGF1 over the signature's hash function.",
                exceptions::Reasons::UNSUPPORTED_MGF,
            )),
        ));
    }

    Ok(SignatureScheme::Pss { hash, salt })
}

enum EncryptionScheme {
    Pkcs1,
    Oaep {
        hash: rsa_oaep::Hash,
        mgf1: rsa_oaep::Hash,
        label: Vec<u8>,
    },
}

/// The scheme of an encryption or decryption, with the errors (and their
/// order) of the OpenSSL backend's `setup_encryption_ctx`.
fn encryption_scheme(
    py: pyo3::Python<'_>,
    padding: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<EncryptionScheme> {
    if !padding.is_instance(&types::ASYMMETRIC_PADDING.get(py)?)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "Padding must be an instance of AsymmetricPadding.",
            ),
        ));
    }

    if padding.is_instance(&types::PKCS1V15.get(py)?)? {
        return Ok(EncryptionScheme::Pkcs1);
    }
    if !padding.is_instance(&types::OAEP.get(py)?)? {
        return Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err((
                format!(
                    "{} is not supported by this backend.",
                    padding.getattr(pyo3::intern!(py, "name"))?
                ),
                exceptions::Reasons::UNSUPPORTED_PADDING,
            )),
        ));
    }
    if !padding
        .getattr(pyo3::intern!(py, "_mgf"))?
        .is_instance(&types::MGF1.get(py)?)?
    {
        return Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err((
                "Only MGF1 is supported.",
                exceptions::Reasons::UNSUPPORTED_MGF,
            )),
        ));
    }

    let mgf1_md = hashes::message_digest_from_algorithm(
        py,
        &padding
            .getattr(pyo3::intern!(py, "_mgf"))?
            .getattr(pyo3::intern!(py, "_algorithm"))?,
    )?;
    let oaep_md = hashes::message_digest_from_algorithm(
        py,
        &padding.getattr(pyo3::intern!(py, "_algorithm"))?,
    )?;
    let (hash, mgf1) = oaep_pair(oaep_md, mgf1_md).ok_or_else(|| {
        exceptions::UnsupportedAlgorithm::new_err((
            "This combination of padding and hash algorithm is not supported",
            exceptions::Reasons::UNSUPPORTED_PADDING,
        ))
    })?;

    let label = padding
        .getattr(pyo3::intern!(py, "_label"))?
        .extract::<Option<pyo3::pybacked::PyBackedBytes>>()?
        .map(|l| l.to_vec())
        .unwrap_or_default();

    Ok(EncryptionScheme::Oaep { hash, mgf1, label })
}

/// The EMSA-PKCS1-v1_5 encoding (RFC 8017 §9.2, steps 3 to 6) of `t` to `k`
/// bytes: `00 01 FF..FF 00 t`, with at least 8 bytes of `FF`.
fn pkcs1_type1_encoding(t: &[u8], k: usize) -> Option<Vec<u8>> {
    if t.len() + 11 > k {
        return None;
    }
    let mut em = vec![0xff; k];
    em[0] = 0;
    em[1] = 1;
    em[k - t.len() - 1] = 0;
    em[k - t.len()..].copy_from_slice(t);
    Some(em)
}

/// The data `t` of an EMSA-PKCS1-v1_5 encoded message (the inverse of
/// `pkcs1_type1_encoding`). Everything here is public.
fn pkcs1_type1_decoding(em: &[u8]) -> Option<&[u8]> {
    let rest = em.strip_prefix(&[0, 1])?;
    let ps = rest.iter().take_while(|&&b| b == 0xff).count();
    if ps < 8 || rest.get(ps) != Some(&0) {
        return None;
    }
    Some(&rest[ps + 1..])
}

fn sign_error() -> CryptographyError {
    CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
        "Digest or salt length too long for key size. Use a larger key or shorter salt length if you are specifying a PSS salt",
    ))
}

/// The maximal PSS salt length for a hash value of `h_len` bytes:
/// `emLen - hLen - 2`, with `emLen = ⌈(modBits - 1) / 8⌉` (RFC 8017 §9.1).
fn pss_max_salt(key_bits: usize, h_len: usize) -> Option<usize> {
    (key_bits - 1).div_ceil(8).checked_sub(h_len + 2)
}

/// `input^e mod n`, if the input is as long as the modulus and below it.
fn public_op(key: &vg_rsa::PublicKey, input: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0; key.modulus_len()];
    key.public_op(input, &mut out).ok()?;
    Some(out)
}

#[pyo3::pymethods]
impl RsaPrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        padding: &pyo3::Bound<'p, pyo3::PyAny>,
        algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyAny>> {
        let (data, algorithm) = {
            if algorithm.is_instance(&types::NO_DIGEST_INFO.get(py)?)? {
                (
                    utils::BytesOrPyBytes::Bytes(data.as_bytes()),
                    pyo3::types::PyNone::get(py).to_owned().into_any(),
                )
            } else {
                utils::calculate_digest_and_algorithm(py, data.as_bytes(), algorithm)?
            }
        };

        let k = self.key.modulus_len();
        let scheme = signature_scheme(py, padding, &algorithm, k, true)?;
        let data = data.as_bytes();
        let signature = match scheme {
            SignatureScheme::Pkcs1(None) => {
                let em = pkcs1_type1_encoding(data, k).ok_or_else(sign_error)?;
                let mut sig = vec![0; k];
                self.key
                    .private_op(&em, &mut sig)
                    .map_err(|_| CryptographyError::VerifiedGarbage("RSA signing failed"))?;
                sig
            }
            SignatureScheme::Pkcs1(Some(hash)) => rsa_pkcs1_sig::sign(&self.key, data, hash)
                .map_err(|e| match e {
                    rsa_pkcs1_sig::Error::ModulusTooShort => sign_error(),
                    _ => CryptographyError::VerifiedGarbage("RSA signing failed"),
                })?,
            SignatureScheme::Pss { hash, salt } => {
                let h_len = hash.digest_len();
                let salt_len = match salt {
                    PssSalt::Max => {
                        pss_max_salt(self.key_size() as usize, h_len).ok_or_else(sign_error)?
                    }
                    PssSalt::Digest => h_len,
                    PssSalt::Len(len) => len,
                    PssSalt::Auto => unreachable!("refused when signing"),
                };
                rsa_pss::sign(&self.key, data, hash, hash, salt_len).map_err(|e| match e {
                    rsa_pss::Error::SaltTooLong => sign_error(),
                    _ => CryptographyError::VerifiedGarbage("RSA signing failed"),
                })?
            }
        };
        Ok(pyo3::types::PyBytes::new(py, &signature).into_any())
    }

    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: &[u8],
        padding: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if self.key.modulus_len() != ciphertext.len() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Ciphertext length must be equal to key size.",
                ),
            ));
        }

        let scheme = encryption_scheme(py, padding)?;
        // verified-garbage decrypts in constant time. PKCS #1 v1.5 decryption
        // uses implicit rejection: an invalid padding yields a message
        // derived from the key and the ciphertext rather than an error.
        let result = match scheme {
            EncryptionScheme::Pkcs1 => rsa_pkcs1_enc::decrypt(&self.key, ciphertext).ok(),
            EncryptionScheme::Oaep { hash, mgf1, label } => {
                rsa_oaep::decrypt(&self.key, ciphertext, hash, mgf1, &label).ok()
            }
        };
        let Some(mut plaintext) = result else {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Decryption failed"),
            ));
        };
        let py_result = pyo3::types::PyBytes::new(py, &plaintext);
        crate::backend::ec::wipe(&mut plaintext);
        Ok(py_result)
    }

    #[getter]
    fn key_size(&self) -> i32 {
        bit_length(self.key.components()[0]) as i32
    }

    fn public_key(&self) -> RsaPublicKey {
        let [n, e, ..] = self.key.components();
        RsaPublicKey {
            key: Ok(self.public.clone()),
            n: trim_zeros(n).to_vec(),
            e: trim_zeros(e).to_vec(),
        }
    }

    fn private_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<RsaPrivateNumbers> {
        let [n, e, d, p, q, dmp1, dmq1, iqmp] = self.key.components();
        let int = |v: &[u8]| -> CryptographyResult<pyo3::Py<pyo3::types::PyInt>> {
            Ok(utils::be_bytes_to_py_int(py, v)?.extract()?)
        };

        let public_numbers = RsaPublicNumbers {
            e: int(e)?,
            n: int(n)?,
        };
        Ok(RsaPrivateNumbers {
            p: int(p)?,
            q: int(q)?,
            d: int(d)?,
            dmp1: int(dmp1)?,
            dmq1: int(dmq1)?,
            iqmp: int(iqmp)?,
            public_numbers: pyo3::Py::new(py, public_numbers)?,
        })
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let [n, e, d, p, q, dmp1, dmq1, iqmp] =
            slf.get().key.components().map(|v| trim_zeros(v).to_vec());
        let raw_key = raw::PrivateKey::Rsa(raw::RsaPrivateKey {
            n,
            e,
            d,
            p,
            q,
            dmp1,
            dmq1,
            iqmp,
        });
        utils::raw_private_bytes(
            py,
            slf,
            &raw_key,
            encoding,
            format,
            encryption_algorithm,
            true,
            false,
        )
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

impl RsaPublicKey {
    fn vg_key(&self) -> CryptographyResult<&vg_rsa::PublicKey> {
        self.key
            .as_ref()
            .map_err(|reason| unsupported_key(reason.clone()))
    }
}

#[pyo3::pymethods]
impl RsaPublicKey {
    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        padding: &pyo3::Bound<'_, pyo3::PyAny>,
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<()> {
        let (data, algorithm) = {
            if algorithm.is_instance(&types::NO_DIGEST_INFO.get(py)?)? {
                (
                    utils::BytesOrPyBytes::Bytes(data.as_bytes()),
                    pyo3::types::PyNone::get(py).to_owned().into_any(),
                )
            } else {
                utils::calculate_digest_and_algorithm(py, data.as_bytes(), algorithm)?
            }
        };

        let scheme = signature_scheme(py, padding, &algorithm, self.n.len(), false)?;
        let key = self.vg_key()?;
        let data = data.as_bytes();
        let signature = signature.as_bytes();
        let valid = match scheme {
            SignatureScheme::Pkcs1(None) => {
                public_op(key, signature).is_some_and(|em| pkcs1_type1_decoding(&em) == Some(data))
            }
            SignatureScheme::Pkcs1(Some(hash)) => rsa_pkcs1_sig::verify(key, signature, data, hash),
            SignatureScheme::Pss { hash, salt } => {
                let salt_length = match salt {
                    // OpenSSL accepts any salt length when verifying with
                    // either.
                    PssSalt::Max | PssSalt::Auto => rsa_pss::SaltLength::Any,
                    PssSalt::Digest => rsa_pss::SaltLength::Len(hash.digest_len()),
                    PssSalt::Len(len) => rsa_pss::SaltLength::Len(len),
                };
                rsa_pss::verify(key, signature, data, hash, hash, salt_length)
            }
        };
        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        plaintext: &[u8],
        padding: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let scheme = encryption_scheme(py, padding)?;
        let key = self.vg_key()?;
        let encryption_failed = || {
            CryptographyError::from(pyo3::exceptions::PyValueError::new_err("Encryption failed"))
        };
        let ciphertext = match scheme {
            EncryptionScheme::Pkcs1 => {
                rsa_pkcs1_enc::encrypt(key, plaintext).map_err(|e| match e {
                    rsa_pkcs1_enc::Error::MessageTooLong => encryption_failed(),
                    _ => CryptographyError::VerifiedGarbage("RSA encryption failed"),
                })?
            }
            EncryptionScheme::Oaep { hash, mgf1, label } => {
                rsa_oaep::encrypt(key, plaintext, hash, mgf1, &label).map_err(|e| match e {
                    rsa_oaep::Error::MessageTooLong => encryption_failed(),
                    _ => CryptographyError::VerifiedGarbage("RSA encryption failed"),
                })?
            }
        };
        Ok(pyo3::types::PyBytes::new(py, &ciphertext))
    }

    fn recover_data_from_signature<'p>(
        &self,
        py: pyo3::Python<'p>,
        signature: &[u8],
        padding: &pyo3::Bound<'_, pyo3::PyAny>,
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let algorithm = if algorithm.is_instance(&types::NO_DIGEST_INFO.get(py)?)? {
            &pyo3::types::PyNone::get(py).to_owned().into_any()
        } else {
            algorithm
        };
        if algorithm.is_instance(&types::PREHASHED.get(py)?)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Prehashed is only supported in the sign and verify methods. It cannot be used with recover_data_from_signature.",
                ),
            ));
        }

        let scheme = signature_scheme(py, padding, algorithm, self.n.len(), false)?;
        let key = self.vg_key()?;
        let recovered = match scheme {
            SignatureScheme::Pkcs1(None) => public_op(key, signature)
                .and_then(|em| pkcs1_type1_decoding(&em).map(<[u8]>::to_vec)),
            SignatureScheme::Pkcs1(Some(hash)) => rsa_pkcs1_sig::recover(key, signature, hash).ok(),
            SignatureScheme::Pss { .. } => {
                return Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err((
                        format!(
                            "{} is not supported for the RSA signature operation",
                            padding.getattr(pyo3::intern!(py, "name"))?
                        ),
                        exceptions::Reasons::UNSUPPORTED_PADDING,
                    )),
                ));
            }
        };
        let recovered = recovered
            .ok_or_else(|| CryptographyError::from(exceptions::InvalidSignature::new_err(())))?;
        Ok(pyo3::types::PyBytes::new(py, &recovered))
    }

    #[getter]
    fn key_size(&self) -> i32 {
        bit_length(&self.n) as i32
    }

    fn public_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<RsaPublicNumbers> {
        Ok(RsaPublicNumbers {
            e: utils::be_bytes_to_py_int(py, &self.e)?.extract()?,
            n: utils::be_bytes_to_py_int(py, &self.n)?.extract()?,
        })
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_key = raw::PublicKey::Rsa(raw::RsaPublicKey {
            n: slf.get().n.clone(),
            e: slf.get().e.clone(),
        });
        utils::raw_public_bytes(py, slf, &raw_key, encoding, format, true, false)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.n == other.n && self.e == other.e
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.primitives.asymmetric.rsa",
    name = "RSAPrivateNumbers"
)]
struct RsaPrivateNumbers {
    #[pyo3(get)]
    p: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    q: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    d: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    dmp1: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    dmq1: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    iqmp: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    public_numbers: pyo3::Py<RsaPublicNumbers>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.primitives.asymmetric.rsa",
    name = "RSAPublicNumbers"
)]
struct RsaPublicNumbers {
    #[pyo3(get)]
    e: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    n: pyo3::Py<pyo3::types::PyInt>,
}

#[allow(clippy::too_many_arguments)]
fn check_private_key_components(
    p: &pyo3::Bound<'_, pyo3::types::PyInt>,
    q: &pyo3::Bound<'_, pyo3::types::PyInt>,
    private_exponent: &pyo3::Bound<'_, pyo3::types::PyInt>,
    dmp1: &pyo3::Bound<'_, pyo3::types::PyInt>,
    dmq1: &pyo3::Bound<'_, pyo3::types::PyInt>,
    iqmp: &pyo3::Bound<'_, pyo3::types::PyInt>,
    public_exponent: &pyo3::Bound<'_, pyo3::types::PyInt>,
    modulus: &pyo3::Bound<'_, pyo3::types::PyInt>,
) -> CryptographyResult<()> {
    if modulus.lt(3)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("modulus must be >= 3."),
        ));
    }

    if p.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("p must be < modulus."),
        ));
    }

    if q.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("q must be < modulus."),
        ));
    }

    if dmp1.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("dmp1 must be < modulus."),
        ));
    }

    if dmq1.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("dmq1 must be < modulus."),
        ));
    }

    if iqmp.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("iqmp must be < modulus."),
        ));
    }

    if private_exponent.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("private_exponent must be < modulus."),
        ));
    }

    if public_exponent.lt(3)? || public_exponent.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("public_exponent must be >= 3 and < modulus."),
        ));
    }

    if public_exponent.bitand(1)?.eq(0)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("public_exponent must be odd."),
        ));
    }

    if dmp1.bitand(1)?.eq(0)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("dmp1 must be odd."),
        ));
    }

    if dmq1.bitand(1)?.eq(0)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("dmq1 must be odd."),
        ));
    }

    if p.mul(q)?.ne(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("p*q must equal modulus."),
        ));
    }

    Ok(())
}

#[pyo3::pymethods]
impl RsaPrivateNumbers {
    #[new]
    fn new(
        p: pyo3::Py<pyo3::types::PyInt>,
        q: pyo3::Py<pyo3::types::PyInt>,
        d: pyo3::Py<pyo3::types::PyInt>,
        dmp1: pyo3::Py<pyo3::types::PyInt>,
        dmq1: pyo3::Py<pyo3::types::PyInt>,
        iqmp: pyo3::Py<pyo3::types::PyInt>,
        public_numbers: pyo3::Py<RsaPublicNumbers>,
    ) -> RsaPrivateNumbers {
        Self {
            p,
            q,
            d,
            dmp1,
            dmq1,
            iqmp,
            public_numbers,
        }
    }

    #[pyo3(signature = (backend = None, *, unsafe_skip_rsa_key_validation = false))]
    fn private_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<&pyo3::Bound<'_, pyo3::PyAny>>,
        unsafe_skip_rsa_key_validation: bool,
    ) -> CryptographyResult<RsaPrivateKey> {
        let _ = backend;

        let public_numbers = self.public_numbers.get();
        check_private_key_components(
            self.p.bind(py),
            self.q.bind(py),
            self.d.bind(py),
            self.dmp1.bind(py),
            self.dmq1.bind(py),
            self.iqmp.bind(py),
            public_numbers.e.bind(py),
            public_numbers.n.bind(py),
        )?;
        let bytes = |v: &pyo3::Py<pyo3::types::PyInt>| utils::py_int_to_be_bytes(py, v.bind(py));
        private_key_from_components(
            &bytes(&public_numbers.n)?,
            &bytes(&public_numbers.e)?,
            &bytes(&self.d)?,
            &bytes(&self.p)?,
            &bytes(&self.q)?,
            &bytes(&self.dmp1)?,
            &bytes(&self.dmq1)?,
            &bytes(&self.iqmp)?,
            unsafe_skip_rsa_key_validation,
        )
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok((**self.p.bind(py)).eq(other.p.bind(py))?
            && (**self.q.bind(py)).eq(other.q.bind(py))?
            && (**self.d.bind(py)).eq(other.d.bind(py))?
            && (**self.dmp1.bind(py)).eq(other.dmp1.bind(py))?
            && (**self.dmq1.bind(py)).eq(other.dmq1.bind(py))?
            && (**self.iqmp.bind(py)).eq(other.iqmp.bind(py))?
            && self
                .public_numbers
                .bind(py)
                .eq(other.public_numbers.bind(py))?)
    }

    fn __hash__(&self, py: pyo3::Python<'_>) -> CryptographyResult<u64> {
        let mut hasher = DefaultHasher::new();
        self.p.bind(py).hash()?.hash(&mut hasher);
        self.q.bind(py).hash()?.hash(&mut hasher);
        self.d.bind(py).hash()?.hash(&mut hasher);
        self.dmp1.bind(py).hash()?.hash(&mut hasher);
        self.dmq1.bind(py).hash()?.hash(&mut hasher);
        self.iqmp.bind(py).hash()?.hash(&mut hasher);
        self.public_numbers.bind(py).hash()?.hash(&mut hasher);
        Ok(hasher.finish())
    }
}

#[pyo3::pymethods]
impl RsaPublicNumbers {
    #[new]
    fn new(e: pyo3::Py<pyo3::types::PyInt>, n: pyo3::Py<pyo3::types::PyInt>) -> RsaPublicNumbers {
        RsaPublicNumbers { e, n }
    }

    #[pyo3(signature = (backend=None))]
    fn public_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<&pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<RsaPublicKey> {
        let _ = backend;

        // A negative value raises OverflowError, as with OpenSSL.
        let n = utils::py_int_to_be_bytes(py, self.n.bind(py))?;
        let e = utils::py_int_to_be_bytes(py, self.e.bind(py))?;
        public_key_from_components(&n, &e)
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok(
            (**self.e.bind(py)).eq(other.e.bind(py))?
                && (**self.n.bind(py)).eq(other.n.bind(py))?,
        )
    }

    fn __hash__(&self, py: pyo3::Python<'_>) -> CryptographyResult<u64> {
        let mut hasher = DefaultHasher::new();
        self.e.bind(py).hash()?.hash(&mut hasher);
        self.n.bind(py).hash()?.hash(&mut hasher);
        Ok(hasher.finish())
    }

    fn __repr__<'py>(
        &self,
        py: pyo3::Python<'py>,
    ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::types::PyString>> {
        let e = self.e.bind(py);
        let n = self.n.bind(py);
        pyo3::types::PyString::from_fmt(py, format_args!("<RSAPublicNumbers(e={e}, n={n})>"))
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod rsa {
    #[pymodule_export]
    use super::{
        generate_private_key, RsaPrivateKey, RsaPrivateNumbers, RsaPublicKey, RsaPublicNumbers,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keys and signature examples of `pss-vect.txt` (PKCS #1 v2.1's
    /// RSA-PSS vectors: SHA-1, MGF1-SHA-1, 20-byte salts): each key's
    /// fields, in file order, and its examples' (message, salt, signature).
    #[allow(clippy::type_complexity)]
    fn pss_vectors() -> Vec<(Vec<Vec<u8>>, Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>)> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/cryptography_vectors/asymmetric/RSA/pkcs-1v2-1d2-vec/pss-vect.txt"
        );
        let text = std::fs::read_to_string(path).unwrap();
        let mut keys: Vec<(Vec<Vec<u8>>, Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>)> = vec![];
        let mut fields: Vec<(String, Vec<u8>)> = vec![];
        let flush =
            |fields: &mut Vec<(String, Vec<u8>)>,
             keys: &mut Vec<(Vec<Vec<u8>>, Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>)>| {
                let key_fields: Vec<Vec<u8>> = fields
                    .iter()
                    .take_while(|(n, _)| !n.starts_with("Message"))
                    .map(|(_, v)| v.clone())
                    .collect();
                let examples = fields[key_fields.len()..]
                    .chunks(3)
                    .map(|c| (c[0].1.clone(), c[1].1.clone(), c[2].1.clone()))
                    .collect();
                if !key_fields.is_empty() {
                    keys.push((key_fields, examples));
                }
                fields.clear();
            };
        for line in text.lines().map(str::trim) {
            if line.starts_with("# Example") {
                flush(&mut fields, &mut keys);
            } else if let Some(name) = line.strip_prefix("# ") {
                if let Some(name) = name.strip_suffix(':') {
                    fields.push((name.to_string(), vec![]));
                }
            } else if !line.is_empty() && !line.starts_with('#') && !line.starts_with('=') {
                if let Some((_, v)) = fields.last_mut() {
                    v.extend(
                        line.split_whitespace()
                            .map(|b| u8::from_str_radix(b, 16).unwrap()),
                    );
                }
            }
        }
        flush(&mut fields, &mut keys);
        keys
    }

    #[test]
    fn pss_vectors_verify_and_sign() {
        let keys = pss_vectors();
        assert_eq!(keys.len(), 10);
        for (key_fields, examples) in keys {
            // Modulus, exponent, then the private key: modulus, public
            // exponent, exponent, primes, prime exponents, coefficient.
            let [n, e, _, _, d, p, q, dp, dq, qinv] = key_fields.try_into().unwrap();
            let Ok(private) =
                private_key_from_components(&n, &e, &d, &p, &q, &dp, &dq, &qinv, false)
            else {
                panic!("key of {} bits refused", bit_length(&n));
            };
            let public = public_key_from_components(&n, &e).ok().unwrap();
            // A key verified-garbage cannot hold still loads.
            assert!(public_key_from_components(&[10], &[3])
                .ok()
                .unwrap()
                .key
                .is_err());
            assert_eq!(public.n, private.key.components()[0]);
            let bits = bit_length(&n);
            assert_eq!(examples.len(), 6);
            for (message, salt, signature) in examples {
                let digest =
                    cryptography_crypto::hash::hash(MessageDigest::Sha1, &message).unwrap();
                let hash = pss_hash(MessageDigest::Sha1).unwrap();
                for salt_length in [
                    rsa_pss::SaltLength::Len(salt.len()),
                    rsa_pss::SaltLength::Any,
                ] {
                    assert!(rsa_pss::verify(
                        public.key.as_ref().unwrap(),
                        &signature,
                        &digest,
                        hash,
                        hash,
                        salt_length
                    ));
                }
                assert!(!rsa_pss::verify(
                    public.key.as_ref().unwrap(),
                    &signature,
                    &digest,
                    hash,
                    hash,
                    rsa_pss::SaltLength::Len(salt.len() + 1)
                ));
                // Our signature with the maximal salt verifies.
                let max = pss_max_salt(bits, digest.len()).unwrap();
                let ours = rsa_pss::sign(&private.key, &digest, hash, hash, max).unwrap();
                assert!(rsa_pss::verify(
                    public.key.as_ref().unwrap(),
                    &ours,
                    &digest,
                    hash,
                    hash,
                    rsa_pss::SaltLength::Len(max)
                ));
                assert!(rsa_pss::sign(&private.key, &digest, hash, hash, max + 1).is_err());
            }
            // PKCS #1 v1.5 without a DigestInfo: the encoding round-trips
            // through the raw operations.
            let k = n.len();
            let em = pkcs1_type1_encoding(b"data", k).unwrap();
            let mut sig = vec![0; k];
            private.key.private_op(&em, &mut sig).unwrap();
            let recovered = public_op(public.key.as_ref().unwrap(), &sig).unwrap();
            assert_eq!(pkcs1_type1_decoding(&recovered), Some(b"data".as_slice()));
            assert!(pkcs1_type1_encoding(&vec![0; k - 10], k).is_none());
            // A key whose values do not match is refused.
            let mut bad_q = q.clone();
            *bad_q.last_mut().unwrap() ^= 2;
            assert!(
                private_key_from_components(&n, &e, &d, &p, &bad_q, &dp, &dq, &qinv, true).is_err()
            );
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(cmp_be(&[0, 1, 2], &[1, 2]), Ordering::Equal);
        assert_eq!(cmp_be(&[2], &[1, 0]), Ordering::Less);
        assert_eq!(bit_length(&[0, 1, 0]), 9);
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(pss_max_salt(1024, 20), Some(106));
        assert_eq!(pss_max_salt(1025, 20), Some(106));
        assert_eq!(pss_max_salt(1026, 20), Some(107));
        assert!(pkcs1_type1_decoding(&[0, 1, 0xff, 0]).is_none());
        assert!(
            pkcs1_type1_decoding(&[0, 2, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0])
                .is_none()
        );
        assert!(oaep_pair(MessageDigest::Sha256, MessageDigest::Sha1).is_some());
        assert!(oaep_pair(MessageDigest::Sha1, MessageDigest::Sha256).is_none());
        assert!(oaep_pair(MessageDigest::Sha3_256, MessageDigest::Sha3_256).is_none());
    }
}
