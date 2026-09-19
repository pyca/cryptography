// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, PbeParams, Pkcs12PbeParams, SubjectPublicKeyInfo,
};
use cryptography_x509::csr::Attributes;
use cryptography_x509::pkcs8::EncryptedPrivateKeyInfo;

use crate::{ec, pbe, rsa, KeyParsingError, KeyParsingResult, ParsedPrivateKey, PrivateKeyRef};

// RFC 5208 Section 5 (PrivateKeyInfo), extended by RFC 5958 Section 2
// (OneAsymmetricKey), which adds version v2 and an optional public key.
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct PrivateKeyInfo<'a> {
    pub version: u8,
    pub algorithm: AlgorithmIdentifier<'a>,
    pub private_key: &'a [u8],
    #[implicit(0)]
    pub attributes: Option<Attributes<'a>>,
    #[implicit(1)]
    pub public_key: Option<asn1::BitString<'a>>,
}

const PKCS8_VERSION_V1: u8 = 0;
const PKCS8_VERSION_V2: u8 = 1;

// RFC 9935 Section 6
#[cfg(any(
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC,
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
))]
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum MlKemPrivateKey {
    #[implicit(0)]
    Seed([u8; 64]),
}

// RFC 9881 Section 6.5
#[cfg(any(
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC,
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
))]
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum MlDsaPrivateKey {
    #[implicit(0)]
    Seed([u8; 32]),
}

pub fn parse_private_key(data: &[u8]) -> KeyParsingResult<ParsedPrivateKey> {
    let k = asn1::parse_single::<PrivateKeyInfo<'_>>(data)?;
    // RFC 5958 Section 2: v1 is used for keys with no public key, v2 is used
    // when a public key is present (but the public key remains optional).
    match (k.version, &k.public_key) {
        (PKCS8_VERSION_V1, None) | (PKCS8_VERSION_V2, _) => {}
        _ => return Err(crate::KeyParsingError::InvalidKey),
    }
    let key = parse_private_key_inner(&k)?;
    if let Some(public_key) = k.public_key {
        // The key is always constructed from the private key. If a public
        // key is also present, decode it (its encoding is the same as the
        // subjectPublicKey of a SubjectPublicKeyInfo for the same algorithm)
        // and verify that it corresponds to the private key, so that an
        // inconsistent key is rejected rather than silently loaded.
        let public = crate::spki::parse_public_key_info(SubjectPublicKeyInfo {
            algorithm: k.algorithm.clone(),
            subject_public_key: public_key,
        })?;
        let derived = key.public_key()?;
        let actual = crate::spki::serialize_public_key(public.as_key_ref())
            .map_err(|_| KeyParsingError::InvalidKey)?;
        let expected = crate::spki::serialize_public_key(derived.as_key_ref())
            .map_err(|_| KeyParsingError::InvalidKey)?;
        if actual != expected {
            return Err(KeyParsingError::InvalidKey);
        }
    }
    Ok(key)
}

fn parse_private_key_inner(k: &PrivateKeyInfo<'_>) -> KeyParsingResult<ParsedPrivateKey> {
    match &k.algorithm.params {
        AlgorithmParameters::Rsa(_) | AlgorithmParameters::RsaPss(_) => {
            rsa::parse_pkcs1_private_key(k.private_key).map(ParsedPrivateKey::Rsa)
        }
        AlgorithmParameters::Ec(params) => {
            ec::parse_pkcs1_private_key(k.private_key, Some(params.clone()))
                .map(ParsedPrivateKey::Ec)
        }
        AlgorithmParameters::Dsa(params) => {
            let scalar = asn1::parse_single::<asn1::BigUint<'_>>(k.private_key)?;
            let params = openssl_bridge::dsa::ParameterMaterial::from_components(
                openssl_bridge::dsa::Components {
                    p: params.p.as_bytes(),
                    q: params.q.as_bytes(),
                    g: params.g.as_bytes(),
                },
            )?;
            Ok(ParsedPrivateKey::Dsa(
                openssl_bridge::dsa::PrivateKeyMaterial::from_scalar(params, scalar.as_bytes())
                    .map_err(|_| KeyParsingError::InvalidKey)?,
            ))
        }
        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        AlgorithmParameters::Dh(params) => {
            let scalar = asn1::parse_single::<asn1::BigUint<'_>>(k.private_key)?;
            let params =
                openssl_bridge::dh::Parameters::from_components(openssl_bridge::dh::Components {
                    p: params.p.as_bytes(),
                    q: Some(params.q.as_bytes()),
                    g: params.g.as_bytes(),
                })
                .map_err(|_| KeyParsingError::InvalidKey)?;
            Ok(ParsedPrivateKey::Dh(
                openssl_bridge::dh::PrivateKeyMaterial::from_scalar(params, scalar.as_bytes())
                    .map_err(|_| KeyParsingError::InvalidKey)?,
            ))
        }
        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        AlgorithmParameters::DhKeyAgreement(params) => {
            let scalar = asn1::parse_single::<asn1::BigUint<'_>>(k.private_key)?;
            let params =
                openssl_bridge::dh::Parameters::from_components(openssl_bridge::dh::Components {
                    p: params.p.as_bytes(),
                    q: None,
                    g: params.g.as_bytes(),
                })
                .map_err(|_| KeyParsingError::InvalidKey)?;
            Ok(ParsedPrivateKey::Dh(
                openssl_bridge::dh::PrivateKeyMaterial::from_scalar(params, scalar.as_bytes())
                    .map_err(|_| KeyParsingError::InvalidKey)?,
            ))
        }
        AlgorithmParameters::Ed25519 => {
            let bytes: &[u8] = asn1::parse_single(k.private_key)?;
            Ok(ParsedPrivateKey::Ed25519(
                openssl_bridge::curve25519::Ed25519SigningKey::from_seed(
                    bytes.try_into().map_err(|_| KeyParsingError::InvalidKey)?,
                )?,
            ))
        }
        AlgorithmParameters::X25519 => {
            let bytes: &[u8] = asn1::parse_single(k.private_key)?;
            Ok(ParsedPrivateKey::X25519(
                openssl_bridge::curve25519::X25519SecretKey::from_bytes(
                    bytes.try_into().map_err(|_| KeyParsingError::InvalidKey)?,
                )?,
            ))
        }
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        AlgorithmParameters::Ed448 => {
            let bytes: &[u8] = asn1::parse_single(k.private_key)?;
            Ok(ParsedPrivateKey::Ed448(
                openssl_bridge::curve448::Ed448SigningKey::from_seed(
                    bytes.try_into().map_err(|_| KeyParsingError::InvalidKey)?,
                )?,
            ))
        }
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        AlgorithmParameters::X448 => {
            let bytes: &[u8] = asn1::parse_single(k.private_key)?;
            Ok(ParsedPrivateKey::X448(
                openssl_bridge::curve448::X448SecretKey::from_bytes(
                    bytes.try_into().map_err(|_| KeyParsingError::InvalidKey)?,
                )?,
            ))
        }
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        AlgorithmParameters::MlDsa44 => {
            let MlDsaPrivateKey::Seed(mut seed) =
                asn1::parse_single::<MlDsaPrivateKey>(k.private_key)?;
            let key = openssl_bridge::mldsa::PrivateKey::from_seed(
                openssl_bridge::mldsa::Variant::MlDsa44,
                &seed,
            );
            openssl_bridge::secret::erase(&mut seed);
            Ok(ParsedPrivateKey::MlDsa(key?))
        }
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        AlgorithmParameters::MlDsa65 => {
            let MlDsaPrivateKey::Seed(mut seed) =
                asn1::parse_single::<MlDsaPrivateKey>(k.private_key)?;
            let key = openssl_bridge::mldsa::PrivateKey::from_seed(
                openssl_bridge::mldsa::Variant::MlDsa65,
                &seed,
            );
            openssl_bridge::secret::erase(&mut seed);
            Ok(ParsedPrivateKey::MlDsa(key?))
        }
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        AlgorithmParameters::MlDsa87 => {
            let MlDsaPrivateKey::Seed(mut seed) =
                asn1::parse_single::<MlDsaPrivateKey>(k.private_key)?;
            let key = openssl_bridge::mldsa::PrivateKey::from_seed(
                openssl_bridge::mldsa::Variant::MlDsa87,
                &seed,
            );
            openssl_bridge::secret::erase(&mut seed);
            Ok(ParsedPrivateKey::MlDsa(key?))
        }
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        AlgorithmParameters::MlKem768 => {
            let MlKemPrivateKey::Seed(mut seed) =
                asn1::parse_single::<MlKemPrivateKey>(k.private_key)?;
            let key = openssl_bridge::mlkem::PrivateKey::from_seed(
                openssl_bridge::mlkem::Variant::MlKem768,
                &seed,
            );
            openssl_bridge::secret::erase(&mut seed);
            Ok(ParsedPrivateKey::MlKem(key?))
        }
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        AlgorithmParameters::MlKem1024 => {
            let MlKemPrivateKey::Seed(mut seed) =
                asn1::parse_single::<MlKemPrivateKey>(k.private_key)?;
            let key = openssl_bridge::mlkem::PrivateKey::from_seed(
                openssl_bridge::mlkem::Variant::MlKem1024,
                &seed,
            );
            openssl_bridge::secret::erase(&mut seed);
            Ok(ParsedPrivateKey::MlKem(key?))
        }
        _ => Err(KeyParsingError::UnsupportedKeyType(
            k.algorithm.oid().clone(),
        )),
    }
}

fn pkcs12_pbe_decrypt(
    data: &[u8],
    password: &[u8],
    cipher: openssl_bridge::cipher::Cipher,
    hash: openssl_bridge::hash::Algorithm,
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
        cipher.default_key_size()?,
        hash,
    )?;
    let iv = cryptography_crypto::pkcs12::kdf(
        password,
        params.salt,
        cryptography_crypto::pkcs12::KDF_IV_ID,
        params.iterations,
        cipher.iv_size()?,
        hash,
    )?;

    openssl_bridge::cipher::decrypt_padded(cipher, &key, &iv, data)
        .map_err(|_| KeyParsingError::IncorrectPassword)
}

fn pkcs5_pbe_decrypt(
    data: &[u8],
    password: &[u8],
    cipher: openssl_bridge::cipher::Cipher,
    hash: openssl_bridge::hash::Algorithm,
    params: &PbeParams,
) -> KeyParsingResult<Vec<u8>> {
    // PKCS#5 v1.5 uses PBKDF1 with iteration count
    // For PKCS#5 PBE, we need key + IV length
    let key_iv_len = cipher.default_key_size()? + cipher.iv_size()?;
    let key_iv = cryptography_crypto::pbkdf1::pbkdf1(
        hash,
        password,
        params.salt,
        params.iterations,
        key_iv_len,
    )?;

    let key = &key_iv[..cipher.default_key_size()?];
    let iv = &key_iv[cipher.default_key_size()?..];

    openssl_bridge::cipher::decrypt_padded(cipher, key, iv, data)
        .map_err(|_| KeyParsingError::IncorrectPassword)
}

pub fn parse_encrypted_private_key(
    data: &[u8],
    password: Option<&[u8]>,
) -> KeyParsingResult<ParsedPrivateKey> {
    let epki = asn1::parse_single::<EncryptedPrivateKeyInfo<'_>>(data)?;
    let password = match password {
        None | Some(b"") => return Err(KeyParsingError::EncryptedKeyWithoutPassword),
        Some(p) => p,
    };

    let plaintext = match epki.encryption_algorithm.params {
        AlgorithmParameters::PbeWithMd5AndDesCbc(params) => pkcs5_pbe_decrypt(
            epki.encrypted_data,
            password,
            openssl_bridge::cipher::Cipher::DesCbc,
            openssl_bridge::hash::Algorithm::from_name("md5")?,
            &params,
        )?,
        AlgorithmParameters::PbeWithShaAnd3KeyTripleDesCbc(params) => pkcs12_pbe_decrypt(
            epki.encrypted_data,
            password,
            openssl_bridge::cipher::Cipher::TripleDesCbc,
            openssl_bridge::hash::Algorithm::from_name("sha1")?,
            &params,
        )?,
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_RC2"))]
        AlgorithmParameters::PbeWithShaAnd40BitRc2Cbc(params) => pkcs12_pbe_decrypt(
            epki.encrypted_data,
            password,
            openssl_bridge::cipher::Cipher::Rc2_40Cbc,
            openssl_bridge::hash::Algorithm::from_name("sha1")?,
            &params,
        )?,
        #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_RC4"))]
        AlgorithmParameters::PbeWithShaAnd128BitRc4(params) => pkcs12_pbe_decrypt(
            epki.encrypted_data,
            password,
            openssl_bridge::cipher::Cipher::Rc4,
            openssl_bridge::hash::Algorithm::from_name("sha1")?,
            &params,
        )?,
        AlgorithmParameters::Pbes2(params) => {
            let (cipher, iv) = match params.encryption_scheme.params {
                AlgorithmParameters::DesEde3Cbc(ref iv) => {
                    (openssl_bridge::cipher::Cipher::TripleDesCbc, &iv[..])
                }
                AlgorithmParameters::Aes128Cbc(ref iv) => {
                    (openssl_bridge::cipher::Cipher::Aes128Cbc, &iv[..])
                }
                AlgorithmParameters::Aes192Cbc(ref iv) => {
                    (openssl_bridge::cipher::Cipher::Aes192Cbc, &iv[..])
                }
                AlgorithmParameters::Aes256Cbc(ref iv) => {
                    (openssl_bridge::cipher::Cipher::Aes256Cbc, &iv[..])
                }
                #[cfg(not(CRYPTOGRAPHY_OSSLCONF = "OPENSSL_NO_RC2"))]
                AlgorithmParameters::Rc2Cbc(ref params) => {
                    // A version of 58 == 128 bits effective key length. The
                    // default is 32. See RFC 8018 B.2.3.
                    if params.version.unwrap_or(32) != 58 {
                        return Err(KeyParsingError::InvalidKey);
                    }
                    (openssl_bridge::cipher::Cipher::Rc2Cbc, &params.iv[..])
                }
                _ => {
                    return Err(KeyParsingError::UnsupportedEncryptionAlgorithm(
                        params.encryption_scheme.oid().clone(),
                    ))
                }
            };

            let key = match params.key_derivation_func.params {
                AlgorithmParameters::Pbkdf2(pbkdf2_params) => {
                    let mut key = vec![0; cipher.default_key_size()?];
                    let md = match pbkdf2_params.prf.params {
                        AlgorithmParameters::HmacWithSha1(_) => {
                            openssl_bridge::hash::Algorithm::from_name("sha1")?
                        }
                        AlgorithmParameters::HmacWithSha224(_) => {
                            openssl_bridge::hash::Algorithm::from_name("sha224")?
                        }
                        AlgorithmParameters::HmacWithSha256(_) => {
                            openssl_bridge::hash::Algorithm::from_name("sha256")?
                        }
                        AlgorithmParameters::HmacWithSha384(_) => {
                            openssl_bridge::hash::Algorithm::from_name("sha384")?
                        }
                        AlgorithmParameters::HmacWithSha512(_) => {
                            openssl_bridge::hash::Algorithm::from_name("sha512")?
                        }
                        _ => {
                            return Err(KeyParsingError::UnsupportedEncryptionAlgorithm(
                                pbkdf2_params.prf.oid().clone(),
                            ))
                        }
                    };
                    let iterations = i32::try_from(pbkdf2_params.iteration_count)
                        .ok()
                        .and_then(|n| u32::try_from(n).ok())
                        .and_then(std::num::NonZeroU32::new)
                        .ok_or(KeyParsingError::InvalidKey)?;
                    openssl_bridge::kdf::pbkdf2_hmac(
                        md,
                        password,
                        pbkdf2_params.salt,
                        iterations,
                        &mut key,
                    )?;
                    key
                }
                #[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
                AlgorithmParameters::Scrypt(scrypt_params) => {
                    let mut key = vec![0; cipher.default_key_size()?];
                    openssl_bridge::kdf::scrypt(
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

            openssl_bridge::cipher::decrypt_padded(cipher, &key, iv, epki.encrypted_data)
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

pub fn serialize_private_key(key: PrivateKeyRef<'_>) -> crate::KeySerializationResult<Vec<u8>> {
    let (p_bytes, q_bytes, g_bytes, q_optional);
    let (params, private_key_der) = match key {
        PrivateKeyRef::Rsa(parts) => (
            AlgorithmParameters::Rsa(Some(())),
            rsa::serialize_pkcs1_private_key(parts)?,
        ),
        PrivateKeyRef::Ec(key) => (
            AlgorithmParameters::Ec(cryptography_x509::common::EcParameters::NamedCurve(
                ec::group_to_curve_oid(key.curve()),
            )),
            ec::serialize_pkcs1_private_key(key, false)?,
        ),
        PrivateKeyRef::Dsa(key) => {
            let parts = key.parameters().components();
            p_bytes = crate::utils::integer_bytes(parts.p);
            q_bytes = crate::utils::integer_bytes(parts.q);
            g_bytes = crate::utils::integer_bytes(parts.g);
            let private = crate::utils::integer_bytes(key.scalar());
            (
                AlgorithmParameters::Dsa(cryptography_x509::common::DssParams {
                    p: asn1::BigUint::new(p_bytes.as_ref()).unwrap(),
                    q: asn1::BigUint::new(q_bytes.as_ref()).unwrap(),
                    g: asn1::BigUint::new(g_bytes.as_ref()).unwrap(),
                }),
                asn1::write_single(&asn1::BigUint::new(private.as_ref()).unwrap())?,
            )
        }
        PrivateKeyRef::Dh(key) => {
            let parts = key.parameters().components();
            p_bytes = crate::utils::integer_bytes(parts.p);
            g_bytes = crate::utils::integer_bytes(parts.g);
            q_optional = parts.q.map(crate::utils::integer_bytes);
            let private = crate::utils::integer_bytes(key.scalar());
            let params = if let Some(ref q) = q_optional {
                AlgorithmParameters::Dh(cryptography_x509::common::DHXParams {
                    p: asn1::BigUint::new(p_bytes.as_ref()).unwrap(),
                    g: asn1::BigUint::new(g_bytes.as_ref()).unwrap(),
                    q: asn1::BigUint::new(q.as_ref()).unwrap(),
                    j: None,
                    validation_params: None,
                })
            } else {
                AlgorithmParameters::DhKeyAgreement(cryptography_x509::common::BasicDHParams {
                    p: asn1::BigUint::new(p_bytes.as_ref()).unwrap(),
                    g: asn1::BigUint::new(g_bytes.as_ref()).unwrap(),
                    private_value_length: None,
                })
            };
            (
                params,
                asn1::write_single(&asn1::BigUint::new(private.as_ref()).unwrap())?,
            )
        }
        PrivateKeyRef::Ed25519(key) => {
            let bytes = key.to_seed()?;
            (
                AlgorithmParameters::Ed25519,
                asn1::write_single(&bytes.as_ref())?,
            )
        }
        PrivateKeyRef::X25519(key) => {
            let bytes = key.to_bytes()?;
            (
                AlgorithmParameters::X25519,
                asn1::write_single(&bytes.as_ref())?,
            )
        }
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        PrivateKeyRef::Ed448(key) => {
            let bytes = key.to_seed()?;
            (
                AlgorithmParameters::Ed448,
                asn1::write_single(&bytes.as_ref())?,
            )
        }
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        PrivateKeyRef::X448(key) => {
            let bytes = key.to_bytes()?;
            (
                AlgorithmParameters::X448,
                asn1::write_single(&bytes.as_ref())?,
            )
        }
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        PrivateKeyRef::MlDsa(key) => {
            let params = match key.variant() {
                openssl_bridge::mldsa::Variant::MlDsa44 => AlgorithmParameters::MlDsa44,
                openssl_bridge::mldsa::Variant::MlDsa65 => AlgorithmParameters::MlDsa65,
                openssl_bridge::mldsa::Variant::MlDsa87 => AlgorithmParameters::MlDsa87,
            };
            (
                params,
                asn1::write_single(&MlDsaPrivateKey::Seed(*key.seed()))?,
            )
        }
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        PrivateKeyRef::MlKem(key) => {
            let params = match key.variant() {
                openssl_bridge::mlkem::Variant::MlKem768 => AlgorithmParameters::MlKem768,
                openssl_bridge::mlkem::Variant::MlKem1024 => AlgorithmParameters::MlKem1024,
            };
            (
                params,
                asn1::write_single(&MlKemPrivateKey::Seed(*key.seed()))?,
            )
        }
    };
    let private_key_der: openssl_bridge::secret::SecretBytes = private_key_der.into();
    Ok(asn1::write_single(&PrivateKeyInfo {
        version: PKCS8_VERSION_V1,
        algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params,
        },
        private_key: private_key_der.as_ref(),
        attributes: None,
        public_key: None,
    })?)
}

const KDF_ITERATION_COUNT: u64 = 2048;

pub fn serialize_encrypted_private_key(
    key: PrivateKeyRef<'_>,
    password: &[u8],
) -> crate::KeySerializationResult<Vec<u8>> {
    let plaintext_der: openssl_bridge::secret::SecretBytes = serialize_private_key(key)?.into();

    let e = pbe::EncryptionAlgorithm::PBESv2SHA256AndAES256CBC;

    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    openssl_bridge::rand::fill_private(&mut salt)?;
    openssl_bridge::rand::fill_private(&mut iv)?;

    let encrypted_data = e.encrypt(
        password,
        KDF_ITERATION_COUNT,
        &salt,
        &iv,
        plaintext_der.as_ref(),
    )?;
    let encryption_alg = e.algorithm_identifier(KDF_ITERATION_COUNT, &salt, &iv);

    let epki = cryptography_x509::pkcs8::EncryptedPrivateKeyInfo {
        encryption_algorithm: encryption_alg,
        encrypted_data: &encrypted_data,
    };

    Ok(asn1::write_single(&epki)?)
}

/// Arbitrary MAC keys cannot be serialized as asymmetric private keys.
/// ```compile_fail
/// use cryptography_key_parsing::PrivateKeyRef;
/// let key = PrivateKeyRef::Hmac(&[0; 16]);
/// ```
const _: () = ();

#[cfg(any(
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
))]
impl Drop for MlDsaPrivateKey {
    fn drop(&mut self) {
        let Self::Seed(seed) = self;
        openssl_bridge::secret::erase(seed);
    }
}

#[cfg(any(
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
))]
impl Drop for MlKemPrivateKey {
    fn drop(&mut self) {
        let Self::Seed(seed) = self;
        openssl_bridge::secret::erase(seed);
    }
}
