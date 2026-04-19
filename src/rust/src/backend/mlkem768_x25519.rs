// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_openssl::mlkem::MlKemVariant;

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};

// X-Wing KEM (aka MLKEM768-X25519) as specified by draft-connolly-cfrg-xwing-kem
// and used as KEM ID 0x647A in draft-ietf-hpke-pq.

const SEED_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 1216;
const CIPHERTEXT_LENGTH: usize = 1120;

const MLKEM_PUBLIC_KEY_LENGTH: usize = 1184;
const MLKEM_CIPHERTEXT_LENGTH: usize = 1088;
const X25519_KEY_LENGTH: usize = 32;

// `\.//^\` — the X-Wing combiner label.
const XWING_LABEL: &[u8; 6] = b"\\.//^\\";

fn shake256_expand_seed(seed: &[u8; SEED_LENGTH]) -> CryptographyResult<[u8; 96]> {
    let md = openssl::hash::MessageDigest::shake_256();
    let mut out = [0u8; 96];
    openssl::hash::hash_xof(md, seed, &mut out)?;
    Ok(out)
}

fn sha3_256_combine(
    ss_m: &[u8],
    ss_x: &[u8],
    ct_x: &[u8],
    pk_x: &[u8],
) -> CryptographyResult<[u8; 32]> {
    let md = openssl::hash::MessageDigest::sha3_256();
    let mut hasher = openssl::hash::Hasher::new(md)?;
    hasher.update(ss_m)?;
    hasher.update(ss_x)?;
    hasher.update(ct_x)?;
    hasher.update(pk_x)?;
    hasher.update(XWING_LABEL)?;
    let digest = hasher.finish()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn derive_components(
    seed: &[u8; SEED_LENGTH],
) -> CryptographyResult<(
    openssl::pkey::PKey<openssl::pkey::Private>,
    openssl::pkey::PKey<openssl::pkey::Private>,
)> {
    let expanded = shake256_expand_seed(seed)?;
    let mlkem_seed = &expanded[..64];
    let x25519_seed = &expanded[64..96];

    let mlkem_pkey =
        cryptography_openssl::mlkem::new_raw_private_key(MlKemVariant::MlKem768, mlkem_seed)?;
    let x25519_pkey =
        openssl::pkey::PKey::private_key_from_raw_bytes(x25519_seed, openssl::pkey::Id::X25519)?;

    Ok((mlkem_pkey, x25519_pkey))
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mlkem768_x25519",
    name = "MLKEM768X25519PrivateKey"
)]
pub(crate) struct MlKem768X25519PrivateKey {
    seed: [u8; SEED_LENGTH],
    mlkem_pkey: openssl::pkey::PKey<openssl::pkey::Private>,
    x25519_pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mlkem768_x25519",
    name = "MLKEM768X25519PublicKey"
)]
pub(crate) struct MlKem768X25519PublicKey {
    mlkem_pkey: openssl::pkey::PKey<openssl::pkey::Public>,
    x25519_pkey: openssl::pkey::PKey<openssl::pkey::Public>,
    pk_bytes: [u8; PUBLIC_KEY_LENGTH],
}

impl MlKem768X25519PrivateKey {
    fn from_seed(seed: [u8; SEED_LENGTH]) -> CryptographyResult<Self> {
        let (mlkem_pkey, x25519_pkey) = derive_components(&seed)?;
        Ok(MlKem768X25519PrivateKey {
            seed,
            mlkem_pkey,
            x25519_pkey,
        })
    }
}

impl MlKem768X25519PublicKey {
    fn from_components(
        mlkem_pkey: openssl::pkey::PKey<openssl::pkey::Public>,
        x25519_pkey: openssl::pkey::PKey<openssl::pkey::Public>,
    ) -> CryptographyResult<Self> {
        let mlkem_raw = mlkem_pkey.raw_public_key()?;
        let x25519_raw = x25519_pkey.raw_public_key()?;
        assert_eq!(mlkem_raw.len(), MLKEM_PUBLIC_KEY_LENGTH);
        assert_eq!(x25519_raw.len(), X25519_KEY_LENGTH);
        let mut pk_bytes = [0u8; PUBLIC_KEY_LENGTH];
        pk_bytes[..MLKEM_PUBLIC_KEY_LENGTH].copy_from_slice(&mlkem_raw);
        pk_bytes[MLKEM_PUBLIC_KEY_LENGTH..].copy_from_slice(&x25519_raw);
        Ok(MlKem768X25519PublicKey {
            mlkem_pkey,
            x25519_pkey,
            pk_bytes,
        })
    }
}

#[pyo3::pyfunction]
fn generate_key() -> CryptographyResult<MlKem768X25519PrivateKey> {
    let mut seed = [0u8; SEED_LENGTH];
    cryptography_openssl::rand::rand_bytes(&mut seed)?;
    MlKem768X25519PrivateKey::from_seed(seed)
}

#[pyo3::pyfunction]
fn from_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlKem768X25519PrivateKey> {
    let bytes = data.as_bytes();
    if bytes.len() != SEED_LENGTH {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "An ML-KEM-768/X25519 seed is 32 bytes long",
        ));
    }
    let mut seed = [0u8; SEED_LENGTH];
    seed.copy_from_slice(bytes);
    MlKem768X25519PrivateKey::from_seed(seed).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("Failed to derive ML-KEM-768/X25519 key from seed")
    })
}

#[pyo3::pyfunction]
fn from_public_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlKem768X25519PublicKey> {
    let bytes = data.as_bytes();
    if bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "An ML-KEM-768/X25519 public key is 1216 bytes long",
        ));
    }
    let mlkem_raw = &bytes[..MLKEM_PUBLIC_KEY_LENGTH];
    let x25519_raw = &bytes[MLKEM_PUBLIC_KEY_LENGTH..];

    let mlkem_pkey =
        cryptography_openssl::mlkem::new_raw_public_key(MlKemVariant::MlKem768, mlkem_raw)
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "Invalid ML-KEM-768 component in ML-KEM-768/X25519 public key",
                )
            })?;
    let x25519_pkey =
        openssl::pkey::PKey::public_key_from_raw_bytes(x25519_raw, openssl::pkey::Id::X25519)
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "Invalid X25519 component in ML-KEM-768/X25519 public key",
                )
            })?;

    MlKem768X25519PublicKey::from_components(mlkem_pkey, x25519_pkey)
        .map_err(CryptographyError::into)
}

#[pyo3::pymethods]
impl MlKem768X25519PrivateKey {
    fn decapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ct = ciphertext.as_bytes();
        if ct.len() != CIPHERTEXT_LENGTH {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "An ML-KEM-768/X25519 ciphertext is 1120 bytes long",
                ),
            ));
        }
        let ct_m = &ct[..MLKEM_CIPHERTEXT_LENGTH];
        let ct_x = &ct[MLKEM_CIPHERTEXT_LENGTH..];

        let ss_m =
            cryptography_openssl::mlkem::decapsulate(&self.mlkem_pkey, ct_m).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("Invalid ML-KEM-768/X25519 ciphertext")
            })?;

        let ct_x_pkey =
            openssl::pkey::PKey::public_key_from_raw_bytes(ct_x, openssl::pkey::Id::X25519)?;
        let mut deriver = openssl::derive::Deriver::new(&self.x25519_pkey)?;
        deriver.set_peer(&ct_x_pkey)?;
        let ss_x = {
            let mut buf = vec![0u8; deriver.len()?];
            let n = deriver.derive(&mut buf)?;
            assert_eq!(n, buf.len());
            buf
        };

        let pk_x = self.x25519_pkey.raw_public_key()?;

        let shared_secret = sha3_256_combine(&ss_m, &ss_x, ct_x, &pk_x)?;
        Ok(pyo3::types::PyBytes::new(py, &shared_secret))
    }

    fn public_key(&self) -> CryptographyResult<MlKem768X25519PublicKey> {
        let mlkem_raw = self.mlkem_pkey.raw_public_key()?;
        let mlkem_pub =
            cryptography_openssl::mlkem::new_raw_public_key(MlKemVariant::MlKem768, &mlkem_raw)?;
        let x25519_raw = self.x25519_pkey.raw_public_key()?;
        let x25519_pub =
            openssl::pkey::PKey::public_key_from_raw_bytes(&x25519_raw, openssl::pkey::Id::X25519)?;
        MlKem768X25519PublicKey::from_components(mlkem_pub, x25519_pub)
    }

    fn private_bytes_raw<'p>(&self, py: pyo3::Python<'p>) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.seed)
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

#[pyo3::pymethods]
impl MlKem768X25519PublicKey {
    fn encapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyTuple>> {
        let (ct_m, ss_m) =
            cryptography_openssl::mlkem::encapsulate(&self.mlkem_pkey).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("ML-KEM-768/X25519 encapsulation failed")
            })?;

        let ephemeral = openssl::pkey::PKey::generate_x25519()?;
        let ct_x = ephemeral.raw_public_key()?;
        let mut deriver = openssl::derive::Deriver::new(&ephemeral)?;
        deriver.set_peer(&self.x25519_pkey)?;
        let ss_x = {
            let mut buf = vec![0u8; deriver.len()?];
            let n = deriver.derive(&mut buf)?;
            assert_eq!(n, buf.len());
            buf
        };

        let pk_x = self.x25519_pkey.raw_public_key()?;
        let shared_secret = sha3_256_combine(&ss_m, &ss_x, &ct_x, &pk_x)?;

        let mut ct = [0u8; CIPHERTEXT_LENGTH];
        ct[..MLKEM_CIPHERTEXT_LENGTH].copy_from_slice(&ct_m);
        ct[MLKEM_CIPHERTEXT_LENGTH..].copy_from_slice(&ct_x);

        let ss = pyo3::types::PyBytes::new(py, &shared_secret);
        let ct_py = pyo3::types::PyBytes::new(py, &ct);
        Ok(pyo3::types::PyTuple::new(
            py,
            [ss.as_any(), ct_py.as_any()],
        )?)
    }

    fn public_bytes_raw<'p>(&self, py: pyo3::Python<'p>) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.pk_bytes)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pk_bytes == other.pk_bytes
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

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod mlkem768_x25519 {
    #[pymodule_export]
    use super::{
        from_public_bytes, from_seed_bytes, generate_key, MlKem768X25519PrivateKey,
        MlKem768X25519PublicKey,
    };
}
