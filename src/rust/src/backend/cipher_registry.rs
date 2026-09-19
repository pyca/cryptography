// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::HashMap;

use openssl_bridge::cipher::{Cipher, XtsDataUnit};
use openssl_bridge::gcm::GcmCipher;
use pyo3::types::PyAnyMethods;

use crate::error::CryptographyResult;
use crate::types;

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

#[derive(Clone, Copy)]
pub(crate) enum Algorithm {
    Conventional(Cipher),
    Gcm(GcmCipher),
    Xts,
}

pub(crate) struct RegistryCipher {
    pub(crate) name: &'static str,
    pub(crate) algorithm: Algorithm,
}

impl RegistryCipher {
    fn resolve(name: &'static str) -> CryptographyResult<Option<Self>> {
        let (algorithm, available) = if name.ends_with("-GCM") {
            let cipher = GcmCipher::from_name(name)?;
            (Algorithm::Gcm(cipher), cipher.is_available())
        } else if name.ends_with("-XTS") {
            let key_length = if name == "AES-128-XTS" { 32 } else { 64 };
            (Algorithm::Xts, XtsDataUnit::is_available(key_length))
        } else {
            let cipher = Cipher::from_name(name)?;
            (Algorithm::Conventional(cipher), cipher.is_available())
        };
        Ok(available.then_some(Self { name, algorithm }))
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
        name: &'static str,
    ) -> CryptographyResult<()> {
        let Some(cipher) = RegistryCipher::resolve(name)? else {
            return Ok(());
        };
        self.m.insert(
            RegistryKey::new(
                self.py,
                algorithm.clone().unbind(),
                mode.clone().unbind(),
                key_size,
            )?,
            cipher,
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
    static REGISTRY: pyo3::sync::PyOnceLock<HashMap<RegistryKey, RegistryCipher>> =
        pyo3::sync::PyOnceLock::new();

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

        m.add(&aes, &cbc, Some(128), "AES-128-CBC")?;
        m.add(&aes, &cbc, Some(192), "AES-192-CBC")?;
        m.add(&aes, &cbc, Some(256), "AES-256-CBC")?;

        m.add(&aes, &ofb, Some(128), "AES-128-OFB")?;
        m.add(&aes, &ofb, Some(192), "AES-192-OFB")?;
        m.add(&aes, &ofb, Some(256), "AES-256-OFB")?;

        m.add(&aes, &gcm, Some(128), "AES-128-GCM")?;
        m.add(&aes, &gcm, Some(192), "AES-192-GCM")?;
        m.add(&aes, &gcm, Some(256), "AES-256-GCM")?;

        m.add(&aes, &ctr, Some(128), "AES-128-CTR")?;
        m.add(&aes, &ctr, Some(192), "AES-192-CTR")?;
        m.add(&aes, &ctr, Some(256), "AES-256-CTR")?;

        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        {
            m.add(&aes, &cfb8, Some(128), "AES-128-CFB8")?;
            m.add(&aes, &cfb8, Some(192), "AES-192-CFB8")?;
            m.add(&aes, &cfb8, Some(256), "AES-256-CFB8")?;

            m.add(&aes, &cfb, Some(128), "AES-128-CFB")?;
            m.add(&aes, &cfb, Some(192), "AES-192-CFB")?;
            m.add(&aes, &cfb, Some(256), "AES-256-CFB")?;
        }

        m.add(&aes, &ecb, Some(128), "AES-128-ECB")?;
        m.add(&aes, &ecb, Some(192), "AES-192-ECB")?;
        m.add(&aes, &ecb, Some(256), "AES-256-ECB")?;

        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        {
            m.add(&aes, &xts, Some(256), "AES-128-XTS")?;
        }

        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        {
            m.add(&aes, &xts, Some(512), "AES-256-XTS")?;
        }

        m.add(&aes128, &cbc, Some(128), "AES-128-CBC")?;
        m.add(&aes256, &cbc, Some(256), "AES-256-CBC")?;

        m.add(&aes128, &ofb, Some(128), "AES-128-OFB")?;
        m.add(&aes256, &ofb, Some(256), "AES-256-OFB")?;

        m.add(&aes128, &gcm, Some(128), "AES-128-GCM")?;
        m.add(&aes256, &gcm, Some(256), "AES-256-GCM")?;

        m.add(&aes128, &ctr, Some(128), "AES-128-CTR")?;
        m.add(&aes256, &ctr, Some(256), "AES-256-CTR")?;

        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        {
            m.add(&aes128, &cfb8, Some(128), "AES-128-CFB8")?;
            m.add(&aes256, &cfb8, Some(256), "AES-256-CFB8")?;

            m.add(&aes128, &cfb, Some(128), "AES-128-CFB")?;
            m.add(&aes256, &cfb, Some(256), "AES-256-CFB")?;
        }

        m.add(&aes128, &ecb, Some(128), "AES-128-ECB")?;
        m.add(&aes256, &ecb, Some(256), "AES-256-ECB")?;

        m.add(&triple_des, &cbc, Some(192), "DES-EDE3-CBC")?;
        m.add(&triple_des, &ecb, Some(192), "DES-EDE3-ECB")?;
        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        {
            m.add(&triple_des, &cfb8, Some(192), "DES-EDE3-CFB8")?;
            m.add(&triple_des, &cfb, Some(192), "DES-EDE3-CFB")?;
            m.add(&triple_des, &ofb, Some(192), "DES-EDE3-OFB")?;
        }

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAMELLIA"))]
        {
            m.add(&camellia, &cbc, Some(128), "CAMELLIA-128-CBC")?;
            m.add(&camellia, &cbc, Some(192), "CAMELLIA-192-CBC")?;
            m.add(&camellia, &cbc, Some(256), "CAMELLIA-256-CBC")?;

            m.add(&camellia, &ecb, Some(128), "CAMELLIA-128-ECB")?;
            m.add(&camellia, &ecb, Some(192), "CAMELLIA-192-ECB")?;
            m.add(&camellia, &ecb, Some(256), "CAMELLIA-256-ECB")?;

            m.add(&camellia, &ofb, Some(128), "CAMELLIA-128-OFB")?;
            m.add(&camellia, &ofb, Some(192), "CAMELLIA-192-OFB")?;
            m.add(&camellia, &ofb, Some(256), "CAMELLIA-256-OFB")?;

            m.add(&camellia, &cfb, Some(128), "CAMELLIA-128-CFB")?;
            m.add(&camellia, &cfb, Some(192), "CAMELLIA-192-CFB")?;
            m.add(&camellia, &cfb, Some(256), "CAMELLIA-256-CFB")?;
        }

        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_SM4"))]
        {
            m.add(&sm4, &cbc, Some(128), "SM4-CBC")?;
            m.add(&sm4, &ctr, Some(128), "SM4-CTR")?;
            m.add(&sm4, &cfb, Some(128), "SM4-CFB")?;
            m.add(&sm4, &ofb, Some(128), "SM4-OFB")?;
            m.add(&sm4, &ecb, Some(128), "SM4-ECB")?;

            #[cfg(not(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            )))]
            m.add(&sm4, &gcm, Some(128), "SM4-GCM")?;
        }

        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        m.add(&chacha20, none_type.as_any(), None, "CHACHA20")?;

        // Don't register legacy ciphers if they're unavailable. In theory
        // this shouldn't be necessary but OpenSSL 3 will return an EVP_CIPHER
        // even when the cipher is unavailable.
        if cfg!(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )) || types::LEGACY_PROVIDER_LOADED.get(py)?.is_truthy()?
        {
            #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_BF"))]
            {
                m.add(&blowfish, &cbc, None, "BF-CBC")?;
                m.add(&blowfish, &cfb, None, "BF-CFB")?;
                m.add(&blowfish, &ofb, None, "BF-OFB")?;
                m.add(&blowfish, &ecb, None, "BF-ECB")?;
            }
            #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_SEED"))]
            {
                m.add(&seed, &cbc, Some(128), "SEED-CBC")?;
                m.add(&seed, &cfb, Some(128), "SEED-CFB")?;
                m.add(&seed, &ofb, Some(128), "SEED-OFB")?;
                m.add(&seed, &ecb, Some(128), "SEED-ECB")?;
            }

            #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_CAST"))]
            {
                m.add(&cast5, &cbc, None, "CAST5-CBC")?;
                m.add(&cast5, &ecb, None, "CAST5-ECB")?;
                m.add(&cast5, &ofb, None, "CAST5-OFB")?;
                m.add(&cast5, &cfb, None, "CAST5-CFB")?;
            }

            #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_IDEA"))]
            {
                m.add(&idea, &cbc, Some(128), "IDEA-CBC")?;
                m.add(&idea, &ecb, Some(128), "IDEA-ECB")?;
                m.add(&idea, &ofb, Some(128), "IDEA-OFB")?;
                m.add(&idea, &cfb, Some(128), "IDEA-CFB")?;
            }

            #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_RC4"))]
            m.add(&arc4, none_type.as_any(), None, "RC4")?;

            m.add(&des, &cbc, Some(64), "DES-CBC")?;

            m.add(&rc2, &cbc, Some(128), "RC2-CBC")?;
        }

        Ok(m.build())
    })
}

pub(crate) fn get_cipher<'py>(
    py: pyo3::Python<'py>,
    algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    mode_cls: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Option<&'py RegistryCipher>> {
    let registry = get_cipher_registry(py)?;

    let key_size = algorithm
        .getattr(pyo3::intern!(py, "key_size"))?
        .extract()?;
    let key = RegistryKey::new(py, algorithm.get_type().into(), mode_cls.into(), key_size)?;

    Ok(registry.get(&key))
}
