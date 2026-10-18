// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! PKCS #8 (and RFC 5958 `OneAsymmetricKey`) private keys, as raw
//! components, and their encryption (PBES1, PBES2 and PKCS #12 PBE) with
//! verified-garbage.

use std::num::NonZeroU32;

use cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, EcParameters, PbeParams, Pkcs12PbeParams,
    SubjectPublicKeyInfo,
};
use cryptography_x509::pkcs8::EncryptedPrivateKeyInfo;

pub use crate::common::{MlDsaPrivateKey, MlKemPrivateKey, PrivateKeyInfo};
use crate::common::{KDF_ITERATION_COUNT, PKCS8_VERSION_V1};
use crate::raw::{DhParameters, DhPrivateKey, DsaParameters, DsaPrivateKey, PrivateKey, PublicKey};
use crate::spki::EncodedParams;
use crate::vg_cipher::Cipher;
use crate::vg_util::{big_uint, curve_field_len, der_uint, ec_points_eq, rand_bytes, uint};
use crate::{
    ec, pbe, rsa, KeyParsingError, KeyParsingResult, ParsedPrivateKey, MIN_DH_MODULUS_SIZE,
};

pub fn parse_private_key(data: &[u8]) -> KeyParsingResult<ParsedPrivateKey> {
    let k = crate::common::parse_private_key_info(data)?;
    let mut key = parse_private_key_inner(&k)?;
    if let Some(public_key) = k.public_key {
        // The key is always constructed from the private key. If a public
        // key is also present, decode it (its encoding is the same as the
        // subjectPublicKey of a SubjectPublicKeyInfo for the same algorithm)
        // and verify that it corresponds to the private key, so that an
        // inconsistent key is rejected rather than silently loaded.
        let public_key = crate::spki::parse_public_key_info(SubjectPublicKeyInfo {
            algorithm: k.algorithm.clone(),
            subject_public_key: public_key,
        })?;
        check_public_key(&mut key, public_key)?;
    }
    Ok(ParsedPrivateKey::Raw(key))
}

/// Checks that `public` is `key`'s public key, or (for EC keys without a
/// public point and for DSA keys) gives `key` the public value, which the
/// backend then checks against the private value as it does for a public
/// value parsed with the private key.
fn check_public_key(key: &mut PrivateKey, public: PublicKey) -> KeyParsingResult<()> {
    let matches = match (&mut *key, public) {
        (PrivateKey::Rsa(k), PublicKey::Rsa(p)) | (PrivateKey::RsaPss(k), PublicKey::RsaPss(p)) => {
            k.n == p.n && k.e == p.e
        }
        (PrivateKey::Ec(k), PublicKey::Ec(p)) => match &k.public_point {
            Some(point) => {
                let field_len = curve_field_len(&k.curve).unwrap();
                k.curve == p.curve && ec_points_eq(point, &p.point, field_len)
            }
            None => {
                k.public_point = Some(p.point);
                k.curve == p.curve
            }
        },
        (PrivateKey::Dsa(k), PublicKey::Dsa(p)) => {
            k.y = Some(p.y);
            k.params == p.params
        }
        (PrivateKey::Dh(k), PublicKey::Dh(p)) => {
            k.params == p.params
                && verified_garbage::ffdh::Parameters::from_components(
                    &k.params.p,
                    &k.params.g,
                    k.params.q.as_deref(),
                )
                .and_then(|params| {
                    verified_garbage::ffdh::PrivateKey::from_components(&params, &p.y, &k.x)
                })
                .is_ok()
        }
        (PrivateKey::X25519(k), PublicKey::X25519(p)) => {
            verified_garbage::x25519::PrivateKey::from_bytes(k).public_key() == p
        }
        (PrivateKey::X448(k), PublicKey::X448(p)) => {
            verified_garbage::x448::PrivateKey::from_bytes(k).public_key() == p
        }
        (PrivateKey::Ed25519(k), PublicKey::Ed25519(p)) => {
            *verified_garbage::ed25519::SigningKey::from_seed(k)
                .verifying_key()
                .as_bytes()
                == p
        }
        (PrivateKey::Ed448(k), PublicKey::Ed448(p)) => {
            *verified_garbage::ed448::SigningKey::from_seed(k)
                .verifying_key()
                .as_bytes()
                == p
        }
        (PrivateKey::MlKem768(seed), PublicKey::MlKem768(p)) => {
            verified_garbage::mlkem768::DecapsulationKey768::from_seed(seed)
                .is_ok_and(|k| k.encapsulation_key().as_bytes()[..] == p[..])
        }
        (PrivateKey::MlKem1024(seed), PublicKey::MlKem1024(p)) => {
            verified_garbage::mlkem1024::DecapsulationKey1024::from_seed(seed)
                .is_ok_and(|k| k.encapsulation_key().as_bytes()[..] == p[..])
        }
        (PrivateKey::MlDsa44(seed), PublicKey::MlDsa44(p)) => {
            verified_garbage::mldsa44::SigningKey44::from_seed(seed)
                .is_ok_and(|k| k.verifying_key().as_bytes()[..] == p[..])
        }
        (PrivateKey::MlDsa65(seed), PublicKey::MlDsa65(p)) => {
            verified_garbage::mldsa65::SigningKey65::from_seed(seed)
                .is_ok_and(|k| k.verifying_key().as_bytes()[..] == p[..])
        }
        (PrivateKey::MlDsa87(seed), PublicKey::MlDsa87(p)) => {
            verified_garbage::mldsa87::SigningKey87::from_seed(seed)
                .is_ok_and(|k| k.verifying_key().as_bytes()[..] == p[..])
        }
        // Both come from the same algorithm identifier, so their types agree.
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(KeyParsingError::InvalidKey)
    }
}

/// A fixed-length raw private key, wrapped in an OCTET STRING (RFC 8410).
fn curve_private_key<const N: usize>(data: &[u8]) -> KeyParsingResult<[u8; N]> {
    let key_bytes = asn1::parse_single::<&[u8]>(data)?;
    key_bytes
        .try_into()
        .map_err(|_| KeyParsingError::InvalidKey)
}

/// The number of bits of an unsigned big-endian integer without leading
/// zeros.
fn bit_len(v: &[u8]) -> usize {
    match v.first() {
        Some(&b) => v.len() * 8 - b.leading_zeros() as usize,
        None => 0,
    }
}

fn parse_dh_private_key(data: &[u8], params: DhParameters) -> KeyParsingResult<PrivateKey> {
    let x = uint(asn1::parse_single::<asn1::BigUint<'_>>(data)?);
    if bit_len(&params.p) < MIN_DH_MODULUS_SIZE as usize {
        return Err(KeyParsingError::InvalidKey);
    }
    Ok(PrivateKey::Dh(DhPrivateKey { params, x }))
}

fn parse_private_key_inner(k: &PrivateKeyInfo<'_>) -> KeyParsingResult<PrivateKey> {
    Ok(match &k.algorithm.params {
        AlgorithmParameters::Rsa(_) => {
            PrivateKey::Rsa(rsa::parse_pkcs1_private_key(k.private_key)?)
        }
        // RSA-PSS keys are treated the same as bare RSA keys.
        AlgorithmParameters::RsaPss(_) => {
            PrivateKey::RsaPss(rsa::parse_pkcs1_private_key(k.private_key)?)
        }
        AlgorithmParameters::Ec(ec_params) => PrivateKey::Ec(ec::parse_pkcs1_private_key(
            k.private_key,
            Some(ec_params.clone()),
        )?),
        AlgorithmParameters::Dsa(dsa_params) => {
            let x = asn1::parse_single::<asn1::BigUint<'_>>(k.private_key)?;
            // PKCS #8 has no `y`: the backend computes it.
            PrivateKey::Dsa(DsaPrivateKey {
                params: DsaParameters {
                    p: uint(dsa_params.p),
                    q: uint(dsa_params.q),
                    g: uint(dsa_params.g),
                },
                x: uint(x),
                y: None,
            })
        }
        AlgorithmParameters::Dh(dh_params) => parse_dh_private_key(
            k.private_key,
            DhParameters {
                p: uint(dh_params.p),
                g: uint(dh_params.g),
                q: Some(uint(dh_params.q)),
            },
        )?,
        AlgorithmParameters::DhKeyAgreement(dh_params) => parse_dh_private_key(
            k.private_key,
            DhParameters {
                p: uint(dh_params.p),
                g: uint(dh_params.g),
                q: None,
            },
        )?,
        AlgorithmParameters::X25519 => PrivateKey::X25519(curve_private_key(k.private_key)?),
        AlgorithmParameters::X448 => PrivateKey::X448(curve_private_key(k.private_key)?),
        AlgorithmParameters::Ed25519 => PrivateKey::Ed25519(curve_private_key(k.private_key)?),
        AlgorithmParameters::Ed448 => PrivateKey::Ed448(curve_private_key(k.private_key)?),
        // Only the seed form is supported (not the expanded key, nor both).
        AlgorithmParameters::MlKem768 => {
            let MlKemPrivateKey::Seed(seed) = asn1::parse_single(k.private_key)?;
            PrivateKey::MlKem768(seed)
        }
        AlgorithmParameters::MlKem1024 => {
            let MlKemPrivateKey::Seed(seed) = asn1::parse_single(k.private_key)?;
            PrivateKey::MlKem1024(seed)
        }
        AlgorithmParameters::MlDsa44 => {
            let MlDsaPrivateKey::Seed(seed) = asn1::parse_single(k.private_key)?;
            PrivateKey::MlDsa44(seed)
        }
        AlgorithmParameters::MlDsa65 => {
            let MlDsaPrivateKey::Seed(seed) = asn1::parse_single(k.private_key)?;
            PrivateKey::MlDsa65(seed)
        }
        AlgorithmParameters::MlDsa87 => {
            let MlDsaPrivateKey::Seed(seed) = asn1::parse_single(k.private_key)?;
            PrivateKey::MlDsa87(seed)
        }
        _ => {
            return Err(KeyParsingError::UnsupportedKeyType(
                k.algorithm.oid().clone(),
            ))
        }
    })
}

fn pkcs12_pbe_decrypt(
    data: &[u8],
    password: &[u8],
    cipher: Cipher,
    params: &Pkcs12PbeParams<'_>,
) -> KeyParsingResult<Vec<u8>> {
    let Ok(password) = std::str::from_utf8(password) else {
        return Err(KeyParsingError::IncorrectPassword);
    };
    let hash = cryptography_crypto::hash::MessageDigest::sha1();
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

    // RC4 derives a (one-byte) IV, as OpenSSL does, but uses none.
    cipher
        .decrypt(&key, &iv[..cipher.iv_len()], data)
        .map_err(|_| KeyParsingError::IncorrectPassword)
}

fn pkcs5_pbe_decrypt(
    data: &[u8],
    password: &[u8],
    cipher: Cipher,
    hash: cryptography_crypto::hash::MessageDigest,
    params: &PbeParams,
) -> KeyParsingResult<Vec<u8>> {
    // PKCS#5 v1.5 uses PBKDF1 with iteration count
    // For PKCS#5 PBE, we need key + IV length
    let key_iv = cryptography_crypto::pbkdf1::pbkdf1(
        hash,
        password,
        params.salt,
        params.iterations,
        cipher.key_len() + cipher.iv_len(),
    )?;
    let (key, iv) = key_iv.split_at(cipher.key_len());

    cipher
        .decrypt(key, iv, data)
        .map_err(|_| KeyParsingError::IncorrectPassword)
}

fn pbkdf2(
    prf: &AlgorithmIdentifier<'_>,
    password: &[u8],
    salt: &[u8],
    iterations: NonZeroU32,
    out: &mut [u8],
) -> KeyParsingResult<()> {
    use verified_garbage::hashes::{sha1::Sha1, sha224::Sha224, sha256::Sha256};
    use verified_garbage::hashes::{sha384::Sha384, sha512::Sha512};
    use verified_garbage::pbkdf2::pbkdf2_hmac;

    match prf.params {
        AlgorithmParameters::HmacWithSha1(_) => {
            pbkdf2_hmac::<Sha1>(password, salt, iterations, out)
        }
        AlgorithmParameters::HmacWithSha224(_) => {
            pbkdf2_hmac::<Sha224>(password, salt, iterations, out)
        }
        AlgorithmParameters::HmacWithSha256(_) => {
            pbkdf2_hmac::<Sha256>(password, salt, iterations, out)
        }
        AlgorithmParameters::HmacWithSha384(_) => {
            pbkdf2_hmac::<Sha384>(password, salt, iterations, out)
        }
        AlgorithmParameters::HmacWithSha512(_) => {
            pbkdf2_hmac::<Sha512>(password, salt, iterations, out)
        }
        _ => {
            return Err(KeyParsingError::UnsupportedEncryptionAlgorithm(
                prf.oid().clone(),
            ))
        }
    }
    Ok(())
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
            Cipher::DesCbc,
            cryptography_crypto::hash::MessageDigest::md5(),
            &params,
        )?,
        AlgorithmParameters::PbeWithShaAnd3KeyTripleDesCbc(params) => {
            pkcs12_pbe_decrypt(epki.encrypted_data, password, Cipher::DesEde3Cbc, &params)?
        }
        AlgorithmParameters::PbeWithShaAnd40BitRc2Cbc(params) => {
            pkcs12_pbe_decrypt(epki.encrypted_data, password, Cipher::Rc2_40Cbc, &params)?
        }
        AlgorithmParameters::PbeWithShaAnd128BitRc4(params) => {
            pkcs12_pbe_decrypt(epki.encrypted_data, password, Cipher::Rc4, &params)?
        }
        AlgorithmParameters::Pbes2(params) => {
            let (cipher, iv) = match params.encryption_scheme.params {
                AlgorithmParameters::DesEde3Cbc(ref iv) => (Cipher::DesEde3Cbc, &iv[..]),
                AlgorithmParameters::Aes128Cbc(ref iv) => (Cipher::Aes128Cbc, &iv[..]),
                AlgorithmParameters::Aes192Cbc(ref iv) => (Cipher::Aes192Cbc, &iv[..]),
                AlgorithmParameters::Aes256Cbc(ref iv) => (Cipher::Aes256Cbc, &iv[..]),
                AlgorithmParameters::Rc2Cbc(ref params) => {
                    // A version of 58 == 128 bits effective key length. The
                    // default is 32. See RFC 8018 B.2.3.
                    if params.version.unwrap_or(32) != 58 {
                        return Err(KeyParsingError::InvalidKey);
                    }
                    (Cipher::Rc2Cbc, &params.iv[..])
                }
                _ => {
                    return Err(KeyParsingError::UnsupportedEncryptionAlgorithm(
                        params.encryption_scheme.oid().clone(),
                    ))
                }
            };

            let mut key = vec![0; cipher.key_len()];
            match params.key_derivation_func.params {
                AlgorithmParameters::Pbkdf2(pbkdf2_params) => {
                    let iterations: usize = pbkdf2_params
                        .iteration_count
                        .try_into()
                        .map_err(|_| KeyParsingError::InvalidKey)?;
                    // verified-garbage takes up to 2^32 - 1 iterations
                    // (OpenSSL takes up to 2^31 - 1).
                    let iterations = u32::try_from(iterations)
                        .ok()
                        .and_then(NonZeroU32::new)
                        .ok_or(KeyParsingError::InvalidKey)?;
                    pbkdf2(
                        &pbkdf2_params.prf,
                        password,
                        pbkdf2_params.salt,
                        iterations,
                        &mut key,
                    )?;
                }
                AlgorithmParameters::Scrypt(scrypt_params) => {
                    let r = u32::try_from(scrypt_params.block_size)
                        .map_err(|_| KeyParsingError::VerifiedGarbage("scrypt"))?;
                    let p = u32::try_from(scrypt_params.parallelization_parameter)
                        .map_err(|_| KeyParsingError::VerifiedGarbage("scrypt"))?;
                    verified_garbage::scrypt::scrypt(
                        password,
                        scrypt_params.salt,
                        scrypt_params.cost_parameter,
                        r,
                        p,
                        usize::MAX / 2,
                        &mut key,
                    )
                    .map_err(|_| KeyParsingError::VerifiedGarbage("scrypt"))?;
                }
                _ => {
                    return Err(KeyParsingError::UnsupportedEncryptionAlgorithm(
                        params.key_derivation_func.oid().clone(),
                    ))
                }
            };

            cipher
                .decrypt(&key, iv, epki.encrypted_data)
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

/// Serializes `key`; an EC key's `public_point` must be present.
pub fn serialize_private_key(key: &ParsedPrivateKey) -> crate::KeySerializationResult<Vec<u8>> {
    let ParsedPrivateKey::Raw(key) = key;
    let encoded_params;

    let (params, private_key_der) = match key {
        // As with OpenSSL, which parses RSA-PSS keys into plain RSA keys,
        // they are serialized as `rsaEncryption` keys.
        PrivateKey::Rsa(rsa) | PrivateKey::RsaPss(rsa) => (
            AlgorithmParameters::Rsa(Some(())),
            rsa::serialize_pkcs1_private_key(rsa)?,
        ),
        PrivateKey::Ec(ec) => (
            AlgorithmParameters::Ec(EcParameters::NamedCurve(ec.curve.clone())),
            ec::serialize_pkcs1_private_key(ec, false)?,
        ),
        PrivateKey::Ed25519(k) => (AlgorithmParameters::Ed25519, asn1::write_single(&&k[..])?),
        PrivateKey::X25519(k) => (AlgorithmParameters::X25519, asn1::write_single(&&k[..])?),
        PrivateKey::Ed448(k) => (AlgorithmParameters::Ed448, asn1::write_single(&&k[..])?),
        PrivateKey::X448(k) => (AlgorithmParameters::X448, asn1::write_single(&&k[..])?),
        PrivateKey::Dsa(dsa) => {
            encoded_params = EncodedParams::dsa(&dsa.params);
            let x = der_uint(&dsa.x);
            (
                encoded_params.dsa_algorithm_parameters(),
                asn1::write_single(&big_uint(&x))?,
            )
        }
        PrivateKey::Dh(dh) => {
            encoded_params = EncodedParams::dh(&dh.params);
            let x = der_uint(&dh.x);
            (
                encoded_params.dh_algorithm_parameters(),
                asn1::write_single(&big_uint(&x))?,
            )
        }
        PrivateKey::MlKem768(seed) => (
            AlgorithmParameters::MlKem768,
            asn1::write_single(&MlKemPrivateKey::Seed(*seed))?,
        ),
        PrivateKey::MlKem1024(seed) => (
            AlgorithmParameters::MlKem1024,
            asn1::write_single(&MlKemPrivateKey::Seed(*seed))?,
        ),
        PrivateKey::MlDsa44(seed) => (
            AlgorithmParameters::MlDsa44,
            asn1::write_single(&MlDsaPrivateKey::Seed(*seed))?,
        ),
        PrivateKey::MlDsa65(seed) => (
            AlgorithmParameters::MlDsa65,
            asn1::write_single(&MlDsaPrivateKey::Seed(*seed))?,
        ),
        PrivateKey::MlDsa87(seed) => (
            AlgorithmParameters::MlDsa87,
            asn1::write_single(&MlDsaPrivateKey::Seed(*seed))?,
        ),
    };

    let pki = PrivateKeyInfo {
        version: PKCS8_VERSION_V1,
        algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params,
        },
        private_key: &private_key_der,
        attributes: None,
        public_key: None,
    };
    Ok(asn1::write_single(&pki)?)
}

pub fn serialize_encrypted_private_key(
    key: &ParsedPrivateKey,
    password: &[u8],
) -> crate::KeySerializationResult<Vec<u8>> {
    let plaintext_der = serialize_private_key(key)?;

    let e = pbe::EncryptionAlgorithm::PBESv2SHA256AndAES256CBC;

    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    rand_bytes(&mut salt)?;
    rand_bytes(&mut iv)?;

    let encrypted_data = e.encrypt(password, KDF_ITERATION_COUNT, &salt, &iv, &plaintext_der)?;
    let encryption_alg = e.algorithm_identifier(KDF_ITERATION_COUNT, &salt, &iv);

    let epki = EncryptedPrivateKeyInfo {
        encryption_algorithm: encryption_alg,
        encrypted_data: &encrypted_data,
    };

    Ok(asn1::write_single(&epki)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vg_util::{pem_vector, vector};
    use cryptography_x509::oid;

    fn parse(data: &[u8]) -> KeyParsingResult<PrivateKey> {
        parse_private_key(data).map(|ParsedPrivateKey::Raw(k)| k)
    }

    fn parse_encrypted(data: &[u8], password: &[u8]) -> KeyParsingResult<PrivateKey> {
        parse_encrypted_private_key(data, Some(password)).map(|ParsedPrivateKey::Raw(k)| k)
    }

    fn serialize(key: &PrivateKey) -> Vec<u8> {
        serialize_private_key(&ParsedPrivateKey::Raw(key.clone()))
            .ok()
            .unwrap()
    }

    /// Parses `der` and checks that serializing gives it back.
    fn round_trip(der: &[u8]) -> PrivateKey {
        let key = parse(der).ok().unwrap();
        assert_eq!(serialize(&key), der);
        key
    }

    #[test]
    fn test_vectors() {
        assert!(matches!(
            round_trip(vector!("DER_Serialization/unenc-rsa-pkcs8.der")),
            PrivateKey::Rsa(_)
        ));
        let PrivateKey::Dsa(dsa) = round_trip(vector!("DER_Serialization/unenc-dsa-pkcs8.der"))
        else {
            panic!()
        };
        assert_eq!(dsa.y, None);
        assert!(matches!(
            round_trip(vector!("Ed25519/ed25519-pkcs8.der")),
            PrivateKey::Ed25519(_)
        ));
        assert!(matches!(
            round_trip(vector!("Ed448/ed448-pkcs8.der")),
            PrivateKey::Ed448(_)
        ));
        assert!(matches!(
            round_trip(vector!("X25519/x25519-pkcs8.der")),
            PrivateKey::X25519(_)
        ));
        assert!(matches!(
            round_trip(vector!("X448/x448-pkcs8.der")),
            PrivateKey::X448(_)
        ));
        assert!(matches!(
            round_trip(vector!("MLDSA/mldsa44_priv.der")),
            PrivateKey::MlDsa44(_)
        ));
        assert!(matches!(
            round_trip(vector!("MLKEM/mlkem768.der")),
            PrivateKey::MlKem768(_)
        ));
        let PrivateKey::Dh(dh) = round_trip(vector!("DH/dhkey.der")) else {
            panic!()
        };
        assert!(dh.params.q.is_none());
        let PrivateKey::Dh(dh) = round_trip(vector!("DH/dhkey_rfc5114_2.der")) else {
            panic!()
        };
        assert!(dh.params.q.is_some());

        let PrivateKey::Ec(ec) = parse(&pem_vector!("PKCS8/ec_private_key.pem"))
            .ok()
            .unwrap()
        else {
            panic!()
        };
        assert!(ec.public_point.is_some());
        assert!(matches!(
            parse(vector!("PKCS8/ec-v2.der")),
            Ok(PrivateKey::Ec(_))
        ));
        assert!(matches!(
            parse(vector!("PKCS8/ec-v2-with-compressed-public-key.der")),
            Ok(PrivateKey::Ec(_))
        ));

        // RSA-PSS keys are RSA keys, serialized as `rsaEncryption` keys.
        let PrivateKey::RsaPss(rsa) = parse(&pem_vector!("PKCS8/rsa_pss_2048.pem")).ok().unwrap()
        else {
            panic!()
        };
        let der = serialize(&PrivateKey::RsaPss(rsa.clone()));
        assert_eq!(der, serialize(&PrivateKey::Rsa(rsa.clone())));
        assert_eq!(parse(&der).ok().unwrap(), PrivateKey::Rsa(rsa));
        for name in [
            "PKCS8/rsa_pss_2048_hash.pem",
            "PKCS8/rsa_pss_2048_hash_mask.pem",
            "PKCS8/rsa_pss_2048_hash_mask_diff.pem",
            "PKCS8/rsa_pss_2048_hash_mask_salt.pem",
        ] {
            let data = std::fs::read(format!(
                "{}/../../../vectors/cryptography_vectors/asymmetric/{name}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            let der = pem::parse(data).unwrap().into_contents();
            assert!(matches!(parse(&der), Ok(PrivateKey::RsaPss(_))));
        }

        // Explicit parameters that are a named curve map to it.
        let PrivateKey::Ec(ec) = parse(&pem_vector!("EC/secp256r1-explicit-seed.pem"))
            .ok()
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(ec.curve, oid::EC_SECP256R1);
        let PrivateKey::Ec(ec) = parse(&pem_vector!("EC/secp521r1-explicit-no-seed.pem"))
            .ok()
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(ec.curve, oid::EC_SECP521R1);
    }

    #[test]
    fn test_errors() {
        assert!(matches!(
            parse(vector!("PKCS8/invalid-version.der")),
            Err(KeyParsingError::InvalidKey)
        ));
        assert!(matches!(
            parse(vector!("PKCS8/ec-v1-with-public-key.der")),
            Err(KeyParsingError::InvalidKey)
        ));
        assert!(matches!(
            parse(vector!("PKCS8/unknown-oid.der")),
            Err(KeyParsingError::UnsupportedKeyType(_))
        ));
        assert!(matches!(
            parse(&pem_vector!("PKCS8/ec-inconsistent-curve.pem")),
            Err(KeyParsingError::InvalidKey)
        ));
        assert!(matches!(
            parse(&pem_vector!("PKCS8/ec-invalid-version.pem")),
            Err(KeyParsingError::InvalidKey)
        ));
        assert!(matches!(
            parse(&pem_vector!("EC/secp256k1-explicit-no-seed.pem")),
            Err(KeyParsingError::ExplicitCurveUnsupported)
        ));
        // ML-DSA keys in the expanded form are not supported.
        assert!(matches!(
            parse(vector!("MLDSA/mldsa65_noseed_priv.der")),
            Err(KeyParsingError::Parse(_))
        ));
        // DH moduli under 512 bits.
        assert!(matches!(
            parse(&pem_vector!("DH/dh_key_256.pem")),
            Err(KeyParsingError::InvalidKey)
        ));
        assert!(matches!(parse(b"\x30\x00"), Err(KeyParsingError::Parse(_))));
    }

    #[test]
    fn test_curve_private_key_lengths() {
        for (params, len) in [
            (AlgorithmParameters::Ed25519, 32),
            (AlgorithmParameters::Ed448, 57),
            (AlgorithmParameters::X25519, 32),
            (AlgorithmParameters::X448, 56),
        ] {
            for n in [len - 1, len + 1] {
                let private_key = asn1::write_single(&vec![1u8; n].as_slice()).unwrap();
                let pki = PrivateKeyInfo {
                    version: 0,
                    algorithm: AlgorithmIdentifier {
                        oid: asn1::DefinedByMarker::marker(),
                        params: params.clone(),
                    },
                    private_key: &private_key,
                    attributes: None,
                    public_key: None,
                };
                let der = asn1::write_single(&pki).unwrap();
                assert!(matches!(parse(&der), Err(KeyParsingError::InvalidKey)));
            }
        }
    }

    #[test]
    fn test_v2_with_public_key() {
        let cases: [(&[u8], &[u8]); 11] = [
            (
                vector!("PKCS8/rsa-v2-with-public-key.der"),
                vector!("PKCS8/rsa-v2-with-wrong-public-key.der"),
            ),
            (
                vector!("PKCS8/ec-v2-with-public-key.der"),
                vector!("PKCS8/ec-v2-with-wrong-public-key.der"),
            ),
            (
                vector!("PKCS8/dsa-v2-with-public-key.der"),
                vector!("PKCS8/dsa-v2-with-wrong-public-key.der"),
            ),
            (
                vector!("PKCS8/dh-pkcs3-v2-with-public-key.der"),
                vector!("PKCS8/dh-pkcs3-v2-with-wrong-public-key.der"),
            ),
            (
                vector!("PKCS8/dh-x942-v2-with-public-key.der"),
                vector!("PKCS8/dh-x942-v2-with-wrong-public-key.der"),
            ),
            (
                vector!("PKCS8/x25519-v2-with-public-key.der"),
                vector!("PKCS8/x25519-v2-with-wrong-public-key.der"),
            ),
            (
                vector!("PKCS8/x448-v2-with-public-key.der"),
                vector!("PKCS8/x448-v2-with-wrong-public-key.der"),
            ),
            (
                vector!("PKCS8/ed25519-v2-with-public-key.der"),
                vector!("PKCS8/ed25519-v2-with-wrong-public-key.der"),
            ),
            (
                vector!("PKCS8/ed448-v2-with-public-key.der"),
                vector!("PKCS8/ed448-v2-with-wrong-public-key.der"),
            ),
            (
                vector!("PKCS8/mlkem768-v2-with-public-key.der"),
                vector!("PKCS8/mlkem768-v2-with-wrong-public-key.der"),
            ),
            (
                vector!("PKCS8/mldsa44-v2-with-public-key.der"),
                vector!("PKCS8/mldsa44-v2-with-wrong-public-key.der"),
            ),
        ];
        for (good, wrong) in cases {
            let key = parse(good).ok().unwrap();
            match &key {
                // The backend checks the public value against the private
                // one: DSA keys carry `y`, and EC keys a public point.
                PrivateKey::Dsa(dsa) => assert!(dsa.y.is_some()),
                PrivateKey::Ec(ec) => assert!(ec.public_point.is_some()),
                _ => {}
            }
            match parse(wrong) {
                Err(KeyParsingError::InvalidKey) => {}
                // A DSA key's `y` is checked by the backend.
                Ok(PrivateKey::Dsa(dsa)) => {
                    let PrivateKey::Dsa(good) = &key else {
                        panic!()
                    };
                    assert_ne!(dsa.y, good.y);
                }
                _ => panic!("a wrong public key was accepted"),
            }
        }
    }

    #[test]
    fn test_v2_ec_public_point_given_to_backend() {
        // An EC key whose ECPrivateKey has no public point takes the
        // OneAsymmetricKey's.
        let point = [&[4u8][..], &[9; 64]].concat();
        let ec = crate::common::EcPrivateKey {
            version: 1,
            private_key: &[1; 32],
            parameters: None,
            public_key: None,
        };
        let ec_der = asn1::write_single(&ec).unwrap();
        let pki = PrivateKeyInfo {
            version: 1,
            algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Ec(EcParameters::NamedCurve(oid::EC_SECP256R1)),
            },
            private_key: &ec_der,
            attributes: None,
            public_key: Some(asn1::BitString::new(&point, 0).unwrap()),
        };
        let der = asn1::write_single(&pki).unwrap();
        let PrivateKey::Ec(key) = parse(&der).ok().unwrap() else {
            panic!()
        };
        assert_eq!(key.public_point, Some(point));
    }

    #[test]
    fn test_encrypted_vectors() {
        let rsa = parse(vector!("DER_Serialization/unenc-rsa-pkcs8.der"))
            .ok()
            .unwrap();
        let cases: [(&[u8], &[u8]); 8] = [
            (vector!("DER_Serialization/enc-rsa-pkcs8.der"), b"foobar"),
            (vector!("DER_Serialization/enc2-rsa-pkcs8.der"), b"baz"),
            (&pem_vector!("PKCS8/enc-rsa-pkcs8.pem"), b"foobar"),
            (&pem_vector!("PKCS8/enc2-rsa-pkcs8.pem"), b"baz"),
            (&pem_vector!("PKCS8/enc-rsa-3des.pem"), b"password"),
            (&pem_vector!("PKCS8/rsa-40bitrc2.pem"), b"baz"),
            (
                &pem_vector!("PKCS8/rsa-pbewithmd5anddescbc.pem"),
                b"hunter2",
            ),
            (&pem_vector!("PKCS8/pkcs12_s2k_pem-X_9607.pem"), b"123456"),
        ];
        for (der, password) in cases {
            assert!(matches!(
                parse_encrypted(der, password),
                Ok(PrivateKey::Rsa(_))
            ));
        }
        // The DER and PEM vectors hold the same key.
        assert_eq!(
            parse_encrypted(vector!("DER_Serialization/enc-rsa-pkcs8.der"), b"foobar")
                .ok()
                .unwrap(),
            parse_encrypted(&pem_vector!("PKCS8/enc-rsa-pkcs8.pem"), b"foobar")
                .ok()
                .unwrap(),
        );
        assert_eq!(
            parse(&pem_vector!("PKCS8/unenc-rsa-pkcs8.pem"))
                .ok()
                .unwrap(),
            rsa
        );

        for (der, password) in [
            (
                &pem_vector!("PKCS8/rsa-aes-192-cbc.pem")[..],
                &b"PolarSSLTest"[..],
            ),
            (
                &pem_vector!("PKCS8/rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.pem"),
                b"PolarSSLTest",
            ),
            (
                &pem_vector!("PKCS8/rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.pem"),
                b"PolarSSLTest",
            ),
            (
                &pem_vector!("PKCS8/rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.pem"),
                b"PolarSSLTest",
            ),
            (
                &pem_vector!("PKCS8/rsa-rc2-cbc.pem"),
                b"Red Hat Enterprise Linux 7.4",
            ),
            (
                &pem_vector!("PKCS8/rsa-pbe-3des-long-salt.pem"),
                b"password",
            ),
        ] {
            assert!(matches!(
                parse_encrypted(der, password),
                Ok(PrivateKey::Rsa(_))
            ));
        }

        assert!(matches!(
            parse_encrypted(&pem_vector!("PKCS8/enc-ec-sha1-128-rc4.pem"), b"password"),
            Ok(PrivateKey::Ec(_))
        ));
        assert!(matches!(
            parse_encrypted(
                vector!("DER_Serialization/ec_private_key_encrypted.der"),
                b"123456"
            ),
            Ok(PrivateKey::Ec(_))
        ));
        assert!(matches!(
            parse_encrypted(&pem_vector!("PKCS8/ed25519-scrypt.pem"), b"hunter42"),
            Ok(PrivateKey::Ed25519(_))
        ));
        for (enc, unenc) in [
            (
                vector!("Ed25519/ed25519-pkcs8-enc.der"),
                vector!("Ed25519/ed25519-pkcs8.der"),
            ),
            (
                vector!("Ed448/ed448-pkcs8-enc.der"),
                vector!("Ed448/ed448-pkcs8.der"),
            ),
            (
                vector!("X25519/x25519-pkcs8-enc.der"),
                vector!("X25519/x25519-pkcs8.der"),
            ),
            (
                vector!("X448/x448-pkcs8-enc.der"),
                vector!("X448/x448-pkcs8.der"),
            ),
        ] {
            let key = parse_encrypted(enc, b"password").ok().unwrap();
            assert_eq!(serialize(&key), unenc);
        }
    }

    #[test]
    fn test_encrypted_errors() {
        let der = vector!("DER_Serialization/enc-rsa-pkcs8.der");
        assert!(matches!(
            parse_encrypted(der, b"wrong"),
            Err(KeyParsingError::IncorrectPassword)
        ));
        for password in [None, Some(&b""[..])] {
            assert!(matches!(
                parse_encrypted_private_key(der, password),
                Err(KeyParsingError::EncryptedKeyWithoutPassword)
            ));
        }
        // PKCS #12 passwords must be UTF-8.
        assert!(matches!(
            parse_encrypted(&pem_vector!("PKCS8/enc-rsa-3des.pem"), b"\xff"),
            Err(KeyParsingError::IncorrectPassword)
        ));
        for name in [
            "enc-unknown-algorithm",
            "enc-unknown-pbkdf2-prf",
            "enc-unknown-kdf",
        ] {
            let data = std::fs::read(format!(
                "{}/../../../vectors/cryptography_vectors/asymmetric/PKCS8/{name}.pem",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            let der = pem::parse(data).unwrap().into_contents();
            assert!(matches!(
                parse_encrypted(&der, b"password"),
                Err(KeyParsingError::UnsupportedEncryptionAlgorithm(_))
            ));
        }
        assert!(matches!(
            parse_encrypted(&pem_vector!("PKCS8/enc-rsa-pkcs8-pbkdf2-0iter.pem"), b"baz"),
            Err(KeyParsingError::InvalidKey)
        ));
        assert!(matches!(
            parse_encrypted(
                &pem_vector!("PKCS8/rsa-rc2-cbc-effective-key-length.pem"),
                b"password"
            ),
            Err(KeyParsingError::InvalidKey)
        ));
    }

    #[test]
    fn test_serialize_encrypted_round_trip() {
        let keys = [
            parse(vector!("DER_Serialization/unenc-rsa-pkcs8.der"))
                .ok()
                .unwrap(),
            parse(&pem_vector!("PKCS8/ec_private_key.pem"))
                .ok()
                .unwrap(),
            PrivateKey::Ed25519([3; 32]),
            PrivateKey::X448([4; 56]),
            PrivateKey::MlKem1024([5; 64]),
            PrivateKey::MlDsa87([6; 32]),
            PrivateKey::MlDsa65([7; 32]),
        ];
        for key in keys {
            let parsed = ParsedPrivateKey::Raw(key.clone());
            let der = serialize_encrypted_private_key(&parsed, b"secret")
                .ok()
                .unwrap();
            assert_eq!(parse_encrypted(&der, b"secret").ok().unwrap(), key);
            assert!(matches!(
                parse_encrypted(&der, b"Secret"),
                Err(KeyParsingError::IncorrectPassword)
            ));
            // Each encryption uses a fresh salt and IV.
            assert_ne!(
                der,
                serialize_encrypted_private_key(&parsed, b"secret")
                    .ok()
                    .unwrap()
            );
        }
    }

    #[test]
    fn test_pkcs12_3des_round_trip() {
        let plaintext = serialize(&PrivateKey::Ed25519([3; 32]));
        let e = pbe::EncryptionAlgorithm::PBESHA1And3KeyTripleDESCBC;
        let salt = [1; 8];
        let encrypted_data = e.encrypt(b"pw", 2048, &salt, &[], &plaintext).ok().unwrap();
        let epki = EncryptedPrivateKeyInfo {
            encryption_algorithm: e.algorithm_identifier(2048, &salt, &[]),
            encrypted_data: &encrypted_data,
        };
        let der = asn1::write_single(&epki).unwrap();
        assert_eq!(
            parse_encrypted(&der, b"pw").ok().unwrap(),
            PrivateKey::Ed25519([3; 32])
        );
        assert!(matches!(
            e.encrypt(b"\xff", 2048, &salt, &[], &plaintext),
            Err(crate::KeySerializationError::PasswordMustBeUtf8)
        ));
        let e = pbe::EncryptionAlgorithm::PBESv2SHA256AndAES256CBC;
        assert!(matches!(
            e.encrypt(b"pw", 0, &[0; 16], &[0; 16], &plaintext),
            Err(crate::KeySerializationError::VerifiedGarbage(_))
        ));
        assert!(matches!(
            e.encrypt(b"pw", 1, &[0; 16], &[0; 8], &plaintext),
            Err(crate::KeySerializationError::VerifiedGarbage(_))
        ));
    }

    #[test]
    fn test_serialize_dh_dsa_round_trip() {
        let dsa = PrivateKey::Dsa(DsaPrivateKey {
            params: DsaParameters {
                p: vec![0x80, 1],
                q: vec![2],
                g: vec![3],
            },
            x: vec![0, 0x90],
            y: Some(vec![5]),
        });
        // `y` is not serialized, and leading zeros are dropped.
        let PrivateKey::Dsa(parsed) = parse(&serialize(&dsa)).ok().unwrap() else {
            panic!()
        };
        assert_eq!(parsed.x, [0x90]);
        assert_eq!(parsed.y, None);
        assert_eq!(parsed.params.p, [0x80, 1]);
    }
}
