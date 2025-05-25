// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::HashMap;

use openssl::cipher::Cipher;
use pyo3::types::PyAnyMethods;

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

enum RegistryCipher {
    Ref(&'static openssl::cipher::CipherRef),
    Owned(Cipher),
}

impl From<&'static openssl::cipher::CipherRef> for RegistryCipher {
    fn from(c: &'static openssl::cipher::CipherRef) -> RegistryCipher {
        RegistryCipher::Ref(c)
    }
}

impl From<Cipher> for RegistryCipher {
    fn from(c: Cipher) -> RegistryCipher {
        RegistryCipher::Owned(c)
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
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
        mode: &pyo3::Bound<'_, pyo3::PyAny>,
        key_size: Option<u16>,
        cipher: impl Into<RegistryCipher>,
    ) -> CryptographyResult<()> {
        self.m.insert(
            RegistryKey::new(
                self.py,
                algorithm.clone().unbind(),
                mode.clone().unbind(),
                key_size,
            )?,
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
        let des = types::DES.get(py)?;
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
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_RC4"))]
        let arc4 = types::ARC4.get(py)?;
        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        let chacha20 = types::CHACHA20.get(py)?;
        let rc2 = types::RC2.get(py)?;

        let cbc = types::CBC.get(py)?;
        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        let cfb = types::CFB.get(py)?;
        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        let cfb8 = types::CFB8.get(py)?;
        let ofb = types::OFB.get(py)?;
        let ecb = types::ECB.get(py)?;
        let ctr = types::CTR.get(py)?;
        let gcm = types::GCM.get(py)?;
        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        let xts = types::XTS.get(py)?;

        let none = py.None();
        let none_type = none.bind(py).get_type();

        m.add(&aes, &cbc, Some(128), Cipher::aes_128_cbc())?;
        m.add(&aes, &cbc, Some(192), Cipher::aes_192_cbc())?;
        m.add(&aes, &cbc, Some(256), Cipher::aes_256_cbc())?;

        m.add(&aes, &ofb, Some(128), Cipher::aes_128_ofb())?;
        m.add(&aes, &ofb, Some(192), Cipher::aes_192_ofb())?;
        m.add(&aes, &ofb, Some(256), Cipher::aes_256_ofb())?;

        m.add(&aes, &gcm, Some(128), Cipher::aes_128_gcm())?;
        m.add(&aes, &gcm, Some(192), Cipher::aes_192_gcm())?;
        m.add(&aes, &gcm, Some(256), Cipher::aes_256_gcm())?;

        m.add(&aes, &ctr, Some(128), Cipher::aes_128_ctr())?;
        m.add(&aes, &ctr, Some(192), Cipher::aes_192_ctr())?;
        m.add(&aes, &ctr, Some(256), Cipher::aes_256_ctr())?;

        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        {
            m.add(&aes, &cfb8, Some(128), Cipher::aes_128_cfb8())?;
            m.add(&aes, &cfb8, Some(192), Cipher::aes_192_cfb8())?;
            m.add(&aes, &cfb8, Some(256), Cipher::aes_256_cfb8())?;

            m.add(&aes, &cfb, Some(128), Cipher::aes_128_cfb128())?;
            m.add(&aes, &cfb, Some(192), Cipher::aes_192_cfb128())?;
            m.add(&aes, &cfb, Some(256), Cipher::aes_256_cfb128())?;
        }

        m.add(&aes, &ecb, Some(128), Cipher::aes_128_ecb())?;
        m.add(&aes, &ecb, Some(192), Cipher::aes_192_ecb())?;
        m.add(&aes, &ecb, Some(256), Cipher::aes_256_ecb())?;

        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        {
            m.add(&aes, &xts, Some(256), Cipher::aes_128_xts())?;
        }

        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        {
            m.add(&aes, &xts, Some(512), Cipher::aes_256_xts())?;
        }

        m.add(&aes128, &cbc, Some(128), Cipher::aes_128_cbc())?;
        m.add(&aes256, &cbc, Some(256), Cipher::aes_256_cbc())?;

        m.add(&aes128, &ofb, Some(128), Cipher::aes_128_ofb())?;
        m.add(&aes256, &ofb, Some(256), Cipher::aes_256_ofb())?;

        m.add(&aes128, &gcm, Some(128), Cipher::aes_128_gcm())?;
        m.add(&aes256, &gcm, Some(256), Cipher::aes_256_gcm())?;

        m.add(&aes128, &ctr, Some(128), Cipher::aes_128_ctr())?;
        m.add(&aes256, &ctr, Some(256), Cipher::aes_256_ctr())?;

        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        {
            m.add(&aes128, &cfb8, Some(128), Cipher::aes_128_cfb8())?;
            m.add(&aes256, &cfb8, Some(256), Cipher::aes_256_cfb8())?;

            m.add(&aes128, &cfb, Some(128), Cipher::aes_128_cfb128())?;
            m.add(&aes256, &cfb, Some(256), Cipher::aes_256_cfb128())?;
        }

        m.add(&aes128, &ecb, Some(128), Cipher::aes_128_ecb())?;
        m.add(&aes256, &ecb, Some(256), Cipher::aes_256_ecb())?;

        m.add(&triple_des, &cbc, Some(192), Cipher::des_ede3_cbc())?;
        m.add(&triple_des, &ecb, Some(192), Cipher::des_ede3_ecb())?;
        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        {
            m.add(&triple_des, &cfb8, Some(192), Cipher::des_ede3_cfb8())?;
            m.add(&triple_des, &cfb, Some(192), Cipher::des_ede3_cfb64())?;
            m.add(&triple_des, &ofb, Some(192), Cipher::des_ede3_ofb())?;
        }

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAMELLIA"))]
        {
            m.add(&camellia, &cbc, Some(128), Cipher::camellia128_cbc())?;
            m.add(&camellia, &cbc, Some(192), Cipher::camellia192_cbc())?;
            m.add(&camellia, &cbc, Some(256), Cipher::camellia256_cbc())?;

            m.add(&camellia, &ecb, Some(128), Cipher::camellia128_ecb())?;
            m.add(&camellia, &ecb, Some(192), Cipher::camellia192_ecb())?;
            m.add(&camellia, &ecb, Some(256), Cipher::camellia256_ecb())?;

            m.add(&camellia, &ofb, Some(128), Cipher::camellia128_ofb())?;
            m.add(&camellia, &ofb, Some(192), Cipher::camellia192_ofb())?;
            m.add(&camellia, &ofb, Some(256), Cipher::camellia256_ofb())?;

            m.add(&camellia, &cfb, Some(128), Cipher::camellia128_cfb128())?;
            m.add(&camellia, &cfb, Some(192), Cipher::camellia192_cfb128())?;
            m.add(&camellia, &cfb, Some(256), Cipher::camellia256_cfb128())?;
        }

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_SM4"))]
        {
            m.add(&sm4, &cbc, Some(128), Cipher::sm4_cbc())?;
            m.add(&sm4, &ctr, Some(128), Cipher::sm4_ctr())?;
            m.add(&sm4, &cfb, Some(128), Cipher::sm4_cfb128())?;
            m.add(&sm4, &ofb, Some(128), Cipher::sm4_ofb())?;
            m.add(&sm4, &ecb, Some(128), Cipher::sm4_ecb())?;

            #[cfg(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER)]
            if let Ok(c) = Cipher::fetch(None, "sm4-gcm", None) {
                m.add(&sm4, &gcm, Some(128), c)?;
            }
        }

        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        m.add(&chacha20, none_type.as_any(), None, Cipher::chacha20())?;

        // Don't register legacy ciphers if they're unavailable. In theory
        // this shouldn't be necessary but OpenSSL 3 will return an EVP_CIPHER
        // even when the cipher is unavailable.
        if cfg!(not(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER))
            || types::LEGACY_PROVIDER_LOADED.get(py)?.is_truthy()?
        {
            #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_BF"))]
            {
                m.add(&blowfish, &cbc, None, Cipher::bf_cbc())?;
                m.add(&blowfish, &cfb, None, Cipher::bf_cfb64())?;
                m.add(&blowfish, &ofb, None, Cipher::bf_ofb())?;
                m.add(&blowfish, &ecb, None, Cipher::bf_ecb())?;
            }
            #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_SEED"))]
            {
                m.add(&seed, &cbc, Some(128), Cipher::seed_cbc())?;
                m.add(&seed, &cfb, Some(128), Cipher::seed_cfb128())?;
                m.add(&seed, &ofb, Some(128), Cipher::seed_ofb())?;
                m.add(&seed, &ecb, Some(128), Cipher::seed_ecb())?;
            }

            #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAST"))]
            {
                m.add(&cast5, &cbc, None, Cipher::cast5_cbc())?;
                m.add(&cast5, &ecb, None, Cipher::cast5_ecb())?;
                m.add(&cast5, &ofb, None, Cipher::cast5_ofb())?;
                m.add(&cast5, &cfb, None, Cipher::cast5_cfb64())?;
            }

            #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_IDEA"))]
            {
                m.add(&idea, &cbc, Some(128), Cipher::idea_cbc())?;
                m.add(&idea, &ecb, Some(128), Cipher::idea_ecb())?;
                m.add(&idea, &ofb, Some(128), Cipher::idea_ofb())?;
                m.add(&idea, &cfb, Some(128), Cipher::idea_cfb64())?;
            }

            #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_RC4"))]
            m.add(&arc4, none_type.as_any(), None, Cipher::rc4())?;

            m.add(&des, &cbc, Some(64), Cipher::des_cbc())?;

            if let Some(rc2_cbc) = Cipher::from_nid(openssl::nid::Nid::RC2_CBC) {
                m.add(&rc2, &cbc, Some(128), rc2_cbc)?;
            }
        }

        Ok(m.build())
    })
}

pub(crate) fn get_cipher<'py>(
    py: pyo3::Python<'py>,
    algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    mode_cls: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Option<&'py openssl::cipher::CipherRef>> {
    let registry = get_cipher_registry(py)?;

    let key_size = algorithm
        .getattr(pyo3::intern!(py, "key_size"))?
        .extract()?;
    let key = RegistryKey::new(py, algorithm.get_type().into(), mode_cls.into(), key_size)?;

    match registry.get(&key) {
        Some(RegistryCipher::Ref(c)) => Ok(Some(c)),
        Some(RegistryCipher::Owned(c)) => Ok(Some(c)),
        None => Ok(None),
    }
}
