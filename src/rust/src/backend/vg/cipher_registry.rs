// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! The ciphers and modes verified-garbage provides, keyed like the OpenSSL
//! build's registry (`backend/cipher_registry.rs`): by the Python algorithm
//! class, the mode class and the key size. It lists exactly the
//! combinations the OpenSSL build registers (with OpenSSL's legacy
//! provider loaded: verified-garbage has no providers, and implements the
//! legacy ciphers), except SM4-GCM, which verified-garbage lacks (OpenSSL
//! registers it only when its provider has it).

use std::collections::HashMap;

use pyo3::types::PyAnyMethods;

use crate::error::CryptographyResult;
use crate::types;

/// A block or stream cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Aes,
    TripleDes,
    /// Single DES, as three-key TDEA with three equal keys.
    Des,
    Camellia,
    Sm4,
    Blowfish,
    Seed,
    Cast5,
    Idea,
    Rc2,
    Rc4,
    ChaCha20,
}

impl Algorithm {
    /// The block size in bytes (1 for the stream ciphers).
    pub(crate) fn block_size(self) -> usize {
        match self {
            Algorithm::Aes | Algorithm::Camellia | Algorithm::Sm4 | Algorithm::Seed => 16,
            Algorithm::TripleDes
            | Algorithm::Des
            | Algorithm::Blowfish
            | Algorithm::Cast5
            | Algorithm::Idea
            | Algorithm::Rc2 => 8,
            Algorithm::Rc4 | Algorithm::ChaCha20 => 1,
        }
    }
}

/// A mode of operation (`Stream` for the stream ciphers, which have none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CipherMode {
    Cbc,
    Ecb,
    /// CFB with segments of a whole block (CFB128, or CFB64 for 64-bit
    /// ciphers).
    Cfb,
    Cfb8,
    Ofb,
    Ctr,
    Gcm,
    Xts,
    Stream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cipher {
    pub(crate) algorithm: Algorithm,
    pub(crate) mode: CipherMode,
}

struct RegistryKey {
    algorithm: pyo3::Py<pyo3::PyAny>,
    mode: pyo3::Py<pyo3::PyAny>,
    key_size: Option<u16>,

    algorithm_hash: isize,
    mode_hash: isize,
}

impl RegistryKey {
    fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Py<pyo3::PyAny>,
        mode: pyo3::Py<pyo3::PyAny>,
        key_size: Option<u16>,
    ) -> CryptographyResult<Self> {
        Ok(Self {
            algorithm: algorithm.clone_ref(py),
            mode: mode.clone_ref(py),
            key_size,
            algorithm_hash: algorithm.bind(py).hash()?,
            mode_hash: mode.bind(py).hash()?,
        })
    }
}

impl PartialEq for RegistryKey {
    fn eq(&self, other: &RegistryKey) -> bool {
        self.algorithm.is(&other.algorithm)
            && self.mode.is(&other.mode)
            && (self.key_size == other.key_size
                || self.key_size.is_none()
                || other.key_size.is_none())
    }
}

impl Eq for RegistryKey {}

impl std::hash::Hash for RegistryKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.algorithm_hash.hash(state);
        self.mode_hash.hash(state);
    }
}

struct RegistryBuilder<'p> {
    py: pyo3::Python<'p>,
    m: HashMap<RegistryKey, Cipher>,
}

impl RegistryBuilder<'_> {
    fn add(
        &mut self,
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
        mode: &pyo3::Bound<'_, pyo3::PyAny>,
        key_sizes: &[Option<u16>],
        cipher: (Algorithm, CipherMode),
    ) -> CryptographyResult<()> {
        for &key_size in key_sizes {
            self.m.insert(
                RegistryKey::new(
                    self.py,
                    algorithm.clone().unbind(),
                    mode.clone().unbind(),
                    key_size,
                )?,
                Cipher {
                    algorithm: cipher.0,
                    mode: cipher.1,
                },
            );
        }
        Ok(())
    }
}

fn get_cipher_registry(py: pyo3::Python<'_>) -> CryptographyResult<&HashMap<RegistryKey, Cipher>> {
    static REGISTRY: pyo3::sync::PyOnceLock<HashMap<RegistryKey, Cipher>> =
        pyo3::sync::PyOnceLock::new();

    REGISTRY.get_or_try_init(py, || {
        let mut m = RegistryBuilder {
            py,
            m: HashMap::new(),
        };

        let aes = types::AES.get(py)?;
        let aes128 = types::AES128.get(py)?;
        let aes256 = types::AES256.get(py)?;
        let triple_des = types::TRIPLE_DES.get(py)?;
        let des = types::DES.get(py)?;
        let camellia = types::CAMELLIA.get(py)?;
        let blowfish = types::BLOWFISH.get(py)?;
        let cast5 = types::CAST5.get(py)?;
        let idea = types::IDEA.get(py)?;
        let sm4 = types::SM4.get(py)?;
        let seed = types::SEED.get(py)?;
        let arc4 = types::ARC4.get(py)?;
        let chacha20 = types::CHACHA20.get(py)?;
        let rc2 = types::RC2.get(py)?;

        let cbc = types::CBC.get(py)?;
        let cfb = types::CFB.get(py)?;
        let cfb8 = types::CFB8.get(py)?;
        let ofb = types::OFB.get(py)?;
        let ecb = types::ECB.get(py)?;
        let ctr = types::CTR.get(py)?;
        let gcm = types::GCM.get(py)?;
        let xts = types::XTS.get(py)?;

        let none = py.None();
        let none_type = none.bind(py).get_type();

        use Algorithm as A;
        use CipherMode as M;

        let aes_sizes = [Some(128), Some(192), Some(256)];
        for (mode, cipher_mode) in [
            (&cbc, M::Cbc),
            (&ofb, M::Ofb),
            (&gcm, M::Gcm),
            (&ctr, M::Ctr),
            (&cfb8, M::Cfb8),
            (&cfb, M::Cfb),
            (&ecb, M::Ecb),
        ] {
            m.add(&aes, mode, &aes_sizes, (A::Aes, cipher_mode))?;
            m.add(&aes128, mode, &[Some(128)], (A::Aes, cipher_mode))?;
            m.add(&aes256, mode, &[Some(256)], (A::Aes, cipher_mode))?;
        }
        // AES-128-XTS and AES-256-XTS (the key is two AES keys).
        m.add(&aes, &xts, &[Some(256), Some(512)], (A::Aes, M::Xts))?;

        for (mode, cipher_mode) in [
            (&cbc, M::Cbc),
            (&ecb, M::Ecb),
            (&cfb8, M::Cfb8),
            (&cfb, M::Cfb),
            (&ofb, M::Ofb),
        ] {
            m.add(&triple_des, mode, &[Some(192)], (A::TripleDes, cipher_mode))?;
        }

        for (mode, cipher_mode) in [
            (&cbc, M::Cbc),
            (&ecb, M::Ecb),
            (&ofb, M::Ofb),
            (&cfb, M::Cfb),
        ] {
            m.add(&camellia, mode, &aes_sizes, (A::Camellia, cipher_mode))?;
            m.add(&blowfish, mode, &[None], (A::Blowfish, cipher_mode))?;
            m.add(&seed, mode, &[Some(128)], (A::Seed, cipher_mode))?;
            m.add(&cast5, mode, &[None], (A::Cast5, cipher_mode))?;
            m.add(&idea, mode, &[Some(128)], (A::Idea, cipher_mode))?;
        }

        for (mode, cipher_mode) in [
            (&cbc, M::Cbc),
            (&ctr, M::Ctr),
            (&cfb, M::Cfb),
            (&ofb, M::Ofb),
            (&ecb, M::Ecb),
        ] {
            m.add(&sm4, mode, &[Some(128)], (A::Sm4, cipher_mode))?;
        }

        m.add(
            &chacha20,
            none_type.as_any(),
            &[None],
            (A::ChaCha20, M::Stream),
        )?;
        m.add(&arc4, none_type.as_any(), &[None], (A::Rc4, M::Stream))?;
        m.add(&des, &cbc, &[Some(64)], (A::Des, M::Cbc))?;
        m.add(&rc2, &cbc, &[Some(128)], (A::Rc2, M::Cbc))?;

        Ok(m.m)
    })
}

pub(crate) fn get_cipher(
    py: pyo3::Python<'_>,
    algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    mode_cls: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Option<Cipher>> {
    let registry = get_cipher_registry(py)?;

    let key_size = algorithm
        .getattr(pyo3::intern!(py, "key_size"))?
        .extract()?;
    let key = RegistryKey::new(py, algorithm.get_type().into(), mode_cls.into(), key_size)?;

    Ok(registry.get(&key).copied())
}
