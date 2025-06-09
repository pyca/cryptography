// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, PbeParams, Pkcs12PbeParams,
};
use cryptography_x509::csr::Attributes;
use cryptography_x509::pkcs8::EncryptedPrivateKeyInfo;

use crate::{ec, rsa, KeyParsingError, KeyParsingResult};

// RFC 5208 Section 5
#[derive(asn1::Asn1Read)]
struct PrivateKeyInfo<'a> {
    version: u8,
    algorithm: AlgorithmIdentifier<'a>,
    private_key: &'a [u8],
    #[implicit(0)]
    _attributes: Option<Attributes<'a>>,
}

pub fn parse_private_key(
    data: &[u8],
) -> KeyParsingResult<openssl::pkey::PKey<openssl::pkey::Private>> {
    let k = asn1::parse_single::<PrivateKeyInfo<'_>>(data)?;
    if k.version != 0 {
        return Err(crate::KeyParsingError::InvalidKey);
    }
    match k.algorithm.params {
        AlgorithmParameters::Rsa(_) | AlgorithmParameters::RsaPss(_) => {
            rsa::parse_pkcs1_private_key(k.private_key)
        }
        AlgorithmParameters::Ec(ec_params) => {
            ec::parse_pkcs1_private_key(k.private_key, Some(ec_params))
        }

        AlgorithmParameters::Dsa(dsa_params) => {
            let private_key_bytes =
                asn1::parse_single::<asn1::BigUint<'_>>(k.private_key)?.as_bytes();
            let dsa_private_key = openssl::bn::BigNum::from_slice(private_key_bytes)?;
            let p = openssl::bn::BigNum::from_slice(dsa_params.p.as_bytes())?;
            let q = openssl::bn::BigNum::from_slice(dsa_params.q.as_bytes())?;
            let g = openssl::bn::BigNum::from_slice(dsa_params.g.as_bytes())?;

            let mut bn_ctx = openssl::bn::BigNumContext::new()?;
            let mut pub_key = openssl::bn::BigNum::new()?;
            pub_key.mod_exp(&g, &dsa_private_key, &p, &mut bn_ctx)?;

            let dsa =
                openssl::dsa::Dsa::from_private_components(p, q, g, dsa_private_key, pub_key)?;
            Ok(openssl::pkey::PKey::from_dsa(dsa)?)
        }

        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        AlgorithmParameters::Dh(dh_params) => {
            let private_key_bytes =
                asn1::parse_single::<asn1::BigUint<'_>>(k.private_key)?.as_bytes();
            let dh_private_key = openssl::bn::BigNum::from_slice(private_key_bytes)?;
            let p = openssl::bn::BigNum::from_slice(dh_params.p.as_bytes())?;
            let g = openssl::bn::BigNum::from_slice(dh_params.g.as_bytes())?;
            let q = openssl::bn::BigNum::from_slice(dh_params.q.as_bytes())?;

            let dh = openssl::dh::Dh::from_params(p, g, q)?;
            let dh = dh.set_private_key(dh_private_key)?;
            Ok(openssl::pkey::PKey::from_dh(dh)?)
        }

        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        AlgorithmParameters::DhKeyAgreement(dh_params) => {
            let private_key_bytes =
                asn1::parse_single::<asn1::BigUint<'_>>(k.private_key)?.as_bytes();
            let dh_private_key = openssl::bn::BigNum::from_slice(private_key_bytes)?;
            let p = openssl::bn::BigNum::from_slice(dh_params.p.as_bytes())?;
            let g = openssl::bn::BigNum::from_slice(dh_params.g.as_bytes())?;

            let dh = openssl::dh::Dh::from_pqg(p, None, g)?;
            let dh = dh.set_private_key(dh_private_key)?;
            Ok(openssl::pkey::PKey::from_dh(dh)?)
        }

        AlgorithmParameters::X25519 => {
            let key_bytes = asn1::parse_single(k.private_key)?;
            Ok(openssl::pkey::PKey::private_key_from_raw_bytes(
                key_bytes,
                openssl::pkey::Id::X25519,
            )?)
        }
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        AlgorithmParameters::X448 => {
            let key_bytes = asn1::parse_single(k.private_key)?;
            Ok(openssl::pkey::PKey::private_key_from_raw_bytes(
                key_bytes,
                openssl::pkey::Id::X448,
            )?)
        }
        AlgorithmParameters::Ed25519 => {
            let key_bytes = asn1::parse_single(k.private_key)?;
            Ok(openssl::pkey::PKey::private_key_from_raw_bytes(
                key_bytes,
                openssl::pkey::Id::ED25519,
            )?)
        }
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        AlgorithmParameters::Ed448 => {
            let key_bytes = asn1::parse_single(k.private_key)?;
            Ok(openssl::pkey::PKey::private_key_from_raw_bytes(
                key_bytes,
                openssl::pkey::Id::ED448,
            )?)
        }

        _ => Err(KeyParsingError::UnsupportedKeyType(
            k.algorithm.oid().clone(),
        )),
    }
}

fn pkcs12_pbe_decrypt(
    data: &[u8],
    password: &[u8],
    cipher: openssl::symm::Cipher,
    hash: openssl::hash::MessageDigest,
    params: &Pkcs12PbeParams<'_>,
) -> KeyParsingResult<Vec<u8>> {
    let Ok(password) = std::str::from_utf8(password) else {
        return Err(KeyParsingError::IncorrectPassword);
    };
    let key = cryptography_crypto::pkcs12::kdf(
        password,
        params.salt,
        cryptography_crypto::pkcs12::KDF_ENCRYPTION_KEY_ID,
        params.iterations,
        cipher.key_len(),
        hash,
    )?;
    let iv = cryptography_crypto::pkcs12::kdf(
        password,
        params.salt,
        cryptography_crypto::pkcs12::KDF_IV_ID,
        params.iterations,
        cipher.block_size(),
        hash,
    )?;

    openssl::symm::decrypt(cipher, &key, Some(&iv), data)
        .map_err(|_| KeyParsingError::IncorrectPassword)
}

fn pkcs5_pbe_decrypt(
    data: &[u8],
    password: &[u8],
    cipher: openssl::symm::Cipher,
    hash: openssl::hash::MessageDigest,
    params: &PbeParams,
) -> KeyParsingResult<Vec<u8>> {
    // PKCS#5 v1.5 uses PBKDF1 with iteration count
    // For PKCS#5 PBE, we need key + IV length
    let key_iv_len = cipher.key_len() + cipher.iv_len().unwrap();
    let key_iv = cryptography_crypto::pbkdf1::pbkdf1(
        hash,
        password,
        params.salt,
        params.iterations,
        key_iv_len,
    )?;

    let key = &key_iv[..cipher.key_len()];
    let iv = &key_iv[cipher.key_len()..];

    openssl::symm::decrypt(cipher, key, Some(iv), data)
        .map_err(|_| KeyParsingError::IncorrectPassword)
}

pub fn parse_encrypted_private_key(
    data: &[u8],
    password: Option<&[u8]>,
) -> KeyParsingResult<openssl::pkey::PKey<openssl::pkey::Private>> {
    let epki = asn1::parse_single::<EncryptedPrivateKeyInfo<'_>>(data)?;
    let password = match password {
        None | Some(b"") => return Err(KeyParsingError::EncryptedKeyWithoutPassword),
        Some(p) => p,
    };

    let plaintext = match epki.encryption_algorithm.params {
        AlgorithmParameters::PbeWithMd5AndDesCbc(params) => pkcs5_pbe_decrypt(
            epki.encrypted_data,
            password,
            openssl::symm::Cipher::des_cbc(),
            openssl::hash::MessageDigest::md5(),
            &params,
        )?,
        AlgorithmParameters::PbeWithShaAnd3KeyTripleDesCbc(params) => pkcs12_pbe_decrypt(
            epki.encrypted_data,
            password,
            openssl::symm::Cipher::des_ede3_cbc(),
            openssl::hash::MessageDigest::sha1(),
            &params,
        )?,
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_RC2"))]
        AlgorithmParameters::PbeWithShaAnd40BitRc2Cbc(params) => pkcs12_pbe_decrypt(
            epki.encrypted_data,
            password,
            openssl::symm::Cipher::rc2_40_cbc(),
            openssl::hash::MessageDigest::sha1(),
            &params,
        )?,
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_RC4"))]
        AlgorithmParameters::PbeWithShaAnd128BitRc4(params) => pkcs12_pbe_decrypt(
            epki.encrypted_data,
            password,
            openssl::symm::Cipher::rc4(),
            openssl::hash::MessageDigest::sha1(),
            &params,
        )?,
        AlgorithmParameters::Pbes2(params) => {
            let (cipher, iv) = match params.encryption_scheme.params {
                AlgorithmParameters::DesEde3Cbc(ref iv) => {
                    (openssl::symm::Cipher::des_ede3_cbc(), &iv[..])
                }
                AlgorithmParameters::Aes128Cbc(ref iv) => {
                    (openssl::symm::Cipher::aes_128_cbc(), &iv[..])
                }
                AlgorithmParameters::Aes192Cbc(ref iv) => {
                    (openssl::symm::Cipher::aes_192_cbc(), &iv[..])
                }
                AlgorithmParameters::Aes256Cbc(ref iv) => {
                    (openssl::symm::Cipher::aes_256_cbc(), &iv[..])
                }
                #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_RC2"))]
                AlgorithmParameters::Rc2Cbc(ref params) => {
                    // A version of 58 == 128 bits effective key length. The
                    // default is 32. See RFC 8018 B.2.3.
                    if params.version.unwrap_or(32) != 58 {
                        return Err(KeyParsingError::InvalidKey);
                    }
                    (openssl::symm::Cipher::rc2_cbc(), &params.iv[..])
                }
                _ => {
                    return Err(KeyParsingError::UnsupportedEncryptionAlgorithm(
                        params.encryption_scheme.oid().clone(),
                    ))
                }
            };

            let key = match params.key_derivation_func.params {
                AlgorithmParameters::Pbkdf2(pbkdf2_params) => {
                    let mut key = vec![0; cipher.key_len()];
                    let md = match pbkdf2_params.prf.params {
                        AlgorithmParameters::HmacWithSha1(_) => {
                            openssl::hash::MessageDigest::sha1()
                        }
                        AlgorithmParameters::HmacWithSha224(_) => {
                            openssl::hash::MessageDigest::sha224()
                        }
                        AlgorithmParameters::HmacWithSha256(_) => {
                            openssl::hash::MessageDigest::sha256()
                        }
                        AlgorithmParameters::HmacWithSha384(_) => {
                            openssl::hash::MessageDigest::sha384()
                        }
                        AlgorithmParameters::HmacWithSha512(_) => {
                            openssl::hash::MessageDigest::sha512()
                        }
                        _ => {
                            return Err(KeyParsingError::UnsupportedEncryptionAlgorithm(
                                pbkdf2_params.prf.oid().clone(),
                            ))
                        }
                    };
                    openssl::pkcs5::pbkdf2_hmac(
                        password,
                        pbkdf2_params.salt,
                        pbkdf2_params
                            .iteration_count
                            .try_into()
                            .map_err(|_| KeyParsingError::InvalidKey)?,
                        md,
                        &mut key,
                    )
                    .unwrap();
                    key
                }
                #[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
                AlgorithmParameters::Scrypt(scrypt_params) => {
                    let mut key = vec![0; cipher.key_len()];
                    openssl::pkcs5::scrypt(
                        password,
                        scrypt_params.salt,
                        scrypt_params.cost_parameter,
                        scrypt_params.block_size,
                        scrypt_params.parallelization_parameter,
                        (usize::MAX / 2).try_into().unwrap(),
                        &mut key,
                    )?;
                    key
                }
                _ => {
                    return Err(KeyParsingError::UnsupportedEncryptionAlgorithm(
                        params.key_derivation_func.oid().clone(),
                    ))
                }
            };

            openssl::symm::decrypt(cipher, &key, Some(iv), epki.encrypted_data)
                .map_err(|_| KeyParsingError::IncorrectPassword)?
        }
        _ => {
            return Err(KeyParsingError::UnsupportedEncryptionAlgorithm(
                epki.encryption_algorithm.oid().clone(),
            ))
        }
    };

    parse_private_key(&plaintext)
}
