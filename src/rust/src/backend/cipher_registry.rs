// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::error::CryptographyResult;
use crate::types;
use openssl::symm::Cipher;
use std::collections::HashMap;

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

fn add_cipher(
    py: pyo3::Python<'_>,
    m: &mut HashMap<RegistryKey, openssl::symm::Cipher>,
    algorithm: &pyo3::PyAny,
    mode: &pyo3::PyAny,
    key_size: Option<u16>,
    cipher: openssl::symm::Cipher,
) -> CryptographyResult<()> {
    m.insert(
        RegistryKey::new(py, algorithm.into(), mode.into(), key_size)?,
        cipher,
    );

    Ok(())
}

fn get_cipher_registry(
    py: pyo3::Python<'_>,
) -> CryptographyResult<&HashMap<RegistryKey, openssl::symm::Cipher>> {
    static REGISTRY: pyo3::once_cell::GILOnceCell<HashMap<RegistryKey, openssl::symm::Cipher>> =
        pyo3::once_cell::GILOnceCell::new();

    REGISTRY.get_or_try_init(py, || {
        let mut r = HashMap::new();
        let m = &mut r;

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

        add_cipher(py, m, aes, cbc, Some(128), Cipher::aes_128_cbc())?;
        add_cipher(py, m, aes, cbc, Some(192), Cipher::aes_192_cbc())?;
        add_cipher(py, m, aes, cbc, Some(256), Cipher::aes_256_cbc())?;

        add_cipher(py, m, aes128, cbc, Some(128), Cipher::aes_128_cbc())?;
        add_cipher(py, m, aes256, cbc, Some(256), Cipher::aes_256_cbc())?;

        add_cipher(py, m, triple_des, cbc, Some(192), Cipher::des_ede3_cbc())?;

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAMELLIA"))]
        add_cipher(py, m, camellia, cbc, Some(128), Cipher::camellia_128_cbc())?;
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAMELLIA"))]
        add_cipher(py, m, camellia, cbc, Some(192), Cipher::camellia_192_cbc())?;
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAMELLIA"))]
        add_cipher(py, m, camellia, cbc, Some(256), Cipher::camellia_256_cbc())?;

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_SM4"))]
        add_cipher(py, m, sm4, cbc, Some(128), Cipher::sm4_cbc())?;

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_SEED"))]
        add_cipher(py, m, seed, cbc, Some(128), Cipher::seed_cbc())?;

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_BF"))]
        add_cipher(py, m, blowfish, cbc, None, Cipher::bf_cbc())?;

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAST"))]
        add_cipher(py, m, cast5, cbc, None, Cipher::cast5_cbc())?;

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_IDEA"))]
        add_cipher(py, m, idea, cbc, Some(128), Cipher::idea_cbc())?;

        Ok(r)
    })
}

pub(crate) fn get_cipher(
    py: pyo3::Python<'_>,
    algorithm: &pyo3::PyAny,
    mode_cls: &pyo3::PyAny,
) -> CryptographyResult<Option<openssl::symm::Cipher>> {
    let registry = get_cipher_registry(py)?;

    let key_size = algorithm
        .getattr(pyo3::intern!(py, "key_size"))?
        .extract()?;
    let key = RegistryKey::new(py, algorithm.get_type().into(), mode_cls.into(), key_size)?;

    Ok(registry.get(&key).cloned())
}
