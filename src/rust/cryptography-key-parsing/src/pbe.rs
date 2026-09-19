// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::{KeySerializationError, KeySerializationResult};

pub enum EncryptionAlgorithm {
    PBESHA1And3KeyTripleDESCBC,
    PBESv2SHA256AndAES256CBC,
}

impl EncryptionAlgorithm {
    pub fn salt_length(&self) -> usize {
        match self {
            EncryptionAlgorithm::PBESHA1And3KeyTripleDESCBC => 8,
            EncryptionAlgorithm::PBESv2SHA256AndAES256CBC => 16,
        }
    }

    pub fn algorithm_identifier<'a>(
        &self,
        cipher_kdf_iter: u64,
        salt: &'a [u8],
        iv: &'a [u8],
    ) -> cryptography_x509::common::AlgorithmIdentifier<'a> {
        match self {
            EncryptionAlgorithm::PBESHA1And3KeyTripleDESCBC => {
                cryptography_x509::common::AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: cryptography_x509::common::AlgorithmParameters::PbeWithShaAnd3KeyTripleDesCbc(cryptography_x509::common::Pkcs12PbeParams{
                        salt,
                        iterations: cipher_kdf_iter,
                    }),
                }
            }
            EncryptionAlgorithm::PBESv2SHA256AndAES256CBC => {
                let kdf_algorithm_identifier = cryptography_x509::common::AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: cryptography_x509::common::AlgorithmParameters::Pbkdf2(
                        cryptography_x509::common::PBKDF2Params {
                            salt,
                            iteration_count: cipher_kdf_iter,
                            key_length: None,
                            prf: Box::new(cryptography_x509::common::AlgorithmIdentifier {
                                oid: asn1::DefinedByMarker::marker(),
                                params:
                                    cryptography_x509::common::AlgorithmParameters::HmacWithSha256(
                                        Some(()),
                                    ),
                            }),
                        },
                    ),
                };
                let encryption_algorithm_identifier =
                    cryptography_x509::common::AlgorithmIdentifier {
                        oid: asn1::DefinedByMarker::marker(),
                        params: cryptography_x509::common::AlgorithmParameters::Aes256Cbc(
                            iv[..16].try_into().unwrap(),
                        ),
                    };

                cryptography_x509::common::AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: cryptography_x509::common::AlgorithmParameters::Pbes2(
                        cryptography_x509::common::PBES2Params {
                            key_derivation_func: Box::new(kdf_algorithm_identifier),
                            encryption_scheme: Box::new(encryption_algorithm_identifier),
                        },
                    ),
                }
            }
        }
    }

    pub fn encrypt(
        &self,
        password: &[u8],
        cipher_kdf_iter: u64,
        salt: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> KeySerializationResult<Vec<u8>> {
        match self {
            EncryptionAlgorithm::PBESHA1And3KeyTripleDESCBC => {
                let password = std::str::from_utf8(password)
                    .map_err(|_| KeySerializationError::PasswordMustBeUtf8)?;

                let key = cryptography_crypto::pkcs12::kdf(
                    password,
                    salt,
                    cryptography_crypto::pkcs12::KDF_ENCRYPTION_KEY_ID,
                    cipher_kdf_iter,
                    24,
                    openssl_bridge::hash::Algorithm::from_name("sha1")?,
                )?;
                let iv = cryptography_crypto::pkcs12::kdf(
                    password,
                    salt,
                    cryptography_crypto::pkcs12::KDF_IV_ID,
                    cipher_kdf_iter,
                    8,
                    openssl_bridge::hash::Algorithm::from_name("sha1")?,
                )?;

                Ok(openssl_bridge::cipher::encrypt_padded(
                    openssl_bridge::cipher::Cipher::TripleDesCbc,
                    &key,
                    &iv,
                    data,
                )?)
            }
            EncryptionAlgorithm::PBESv2SHA256AndAES256CBC => {
                let sha256 = openssl_bridge::hash::Algorithm::from_name("sha256")?;

                let mut key = [0; 32];
                openssl_bridge::kdf::pbkdf2_hmac(
                    sha256,
                    password,
                    salt,
                    u32::try_from(cipher_kdf_iter)
                        .ok()
                        .and_then(std::num::NonZeroU32::new)
                        .ok_or(openssl_bridge::Error::InvalidInput(
                            "invalid PBKDF2 iteration count",
                        ))?,
                    &mut key,
                )?;

                Ok(openssl_bridge::cipher::encrypt_padded(
                    openssl_bridge::cipher::Cipher::Aes256Cbc,
                    &key,
                    iv,
                    data,
                )?)
            }
        }
    }
}
