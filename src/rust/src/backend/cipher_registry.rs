// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::HashMap;

use openssl::cipher::Cipher;

use crate::error::CryptographyResult;
use crate::types;

struct RegistryKey {
    algorithm: pyo3::PyObject,
    mode: pyo3::PyObject,
    key_size: Option<u16>,

    algorithm_hash: isize,
    mode_hash: isize,
}

impl RegistryKey {
    fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::PyObject,
        mode: pyo3::PyObject,
        key_size: Option<u16>,
    ) -> CryptographyResult<Self> {
        Ok(Self {
            algorithm: algorithm.clone_ref(py),
            mode: mode.clone_ref(py),
            key_size,
            algorithm_hash: algorithm.as_ref(py).hash()?,
            mode_hash: mode.as_ref(py).hash()?,
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

enum RegistryCipher {
    Ref(&'static openssl::cipher::CipherRef),
}

impl From<&'static openssl::cipher::CipherRef> for RegistryCipher {
    fn from(c: &'static openssl::cipher::CipherRef) -> RegistryCipher {
        RegistryCipher::Ref(c)
    }
}

struct RegistryBuilder<'p> {
    py: pyo3::Python<'p>,
    m: HashMap<RegistryKey, RegistryCipher>,
}

impl<'p> RegistryBuilder<'p> {
    fn new(py: pyo3::Python<'p>) -> Self {
        RegistryBuilder {
            py,
            m: HashMap::new(),
        }
    }

    fn add(
        &mut self,
        algorithm: &pyo3::PyAny,
        mode: &pyo3::PyAny,
        key_size: Option<u16>,
        cipher: impl Into<RegistryCipher>,
    ) -> CryptographyResult<()> {
        self.m.insert(
            RegistryKey::new(self.py, algorithm.into(), mode.into(), key_size)?,
            cipher.into(),
        );

        Ok(())
    }

    fn build(self) -> HashMap<RegistryKey, RegistryCipher> {
        self.m
    }
}

fn get_cipher_registry(
    py: pyo3::Python<'_>,
) -> CryptographyResult<&HashMap<RegistryKey, RegistryCipher>> {
    static REGISTRY: pyo3::sync::GILOnceCell<HashMap<RegistryKey, RegistryCipher>> =
        pyo3::sync::GILOnceCell::new();

    REGISTRY.get_or_try_init(py, || {
        let mut m = RegistryBuilder::new(py);

        let aes = types::AES.get(py)?;
        let aes128 = types::AES128.get(py)?;
        let aes256 = types::AES256.get(py)?;
        let triple_des = types::TRIPLE_DES.get(py)?;
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAMELLIA"))]
        let camellia = types::CAMELLIA.get(py)?;
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_BF"))]
        let blowfish = types::BLOWFISH.get(py)?;
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAST"))]
        let cast5 = types::CAST5.get(py)?;
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_IDEA"))]
        let idea = types::IDEA.get(py)?;
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_SM4"))]
        let sm4 = types::SM4.get(py)?;
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_SEED"))]
        let seed = types::SEED.get(py)?;

        let cbc = types::CBC.get(py)?;

        m.add(aes, cbc, Some(128), Cipher::aes_128_cbc())?;
        m.add(aes, cbc, Some(192), Cipher::aes_192_cbc())?;
        m.add(aes, cbc, Some(256), Cipher::aes_256_cbc())?;

        m.add(aes128, cbc, Some(128), Cipher::aes_128_cbc())?;
        m.add(aes256, cbc, Some(256), Cipher::aes_256_cbc())?;

        m.add(triple_des, cbc, Some(192), Cipher::des_ede3_cbc())?;

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAMELLIA"))]
        m.add(camellia, cbc, Some(128), Cipher::camellia128_cbc())?;
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAMELLIA"))]
        m.add(camellia, cbc, Some(192), Cipher::camellia192_cbc())?;
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAMELLIA"))]
        m.add(camellia, cbc, Some(256), Cipher::camellia256_cbc())?;

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_SM4"))]
        m.add(sm4, cbc, Some(128), Cipher::sm4_cbc())?;

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_SEED"))]
        m.add(seed, cbc, Some(128), Cipher::seed_cbc())?;

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_BF"))]
        m.add(blowfish, cbc, None, Cipher::bf_cbc())?;

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAST"))]
        m.add(cast5, cbc, None, Cipher::cast5_cbc())?;

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_IDEA"))]
        m.add(idea, cbc, Some(128), Cipher::idea_cbc())?;

        Ok(m.build())
    })
}

pub(crate) fn get_cipher<'a>(
    py: pyo3::Python<'_>,
    algorithm: &pyo3::PyAny,
    mode_cls: &pyo3::PyAny,
) -> CryptographyResult<Option<&'a openssl::cipher::CipherRef>> {
    let registry = get_cipher_registry(py)?;

    let key_size = algorithm
        .getattr(pyo3::intern!(py, "key_size"))?
        .extract()?;
    let key = RegistryKey::new(py, algorithm.get_type().into(), mode_cls.into(), key_size)?;

    match registry.get(&key) {
        Some(RegistryCipher::Ref(c)) => Ok(Some(c)),
        None => Ok(None),
    }
}
