// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! The pure-ASN.1 structures and checks every crypto backend's key parsing
//! shares.

use cryptography_x509::common::{AlgorithmIdentifier, EcParameters};
use cryptography_x509::csr::Attributes;
use cryptography_x509::ec_constants;

use crate::{KeyParsingError, KeyParsingResult};

// RFC 8017, Section A.1.2
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct RsaPrivateKey<'a> {
    pub(crate) version: u8,
    pub(crate) n: asn1::BigUint<'a>,
    pub(crate) e: asn1::BigUint<'a>,
    pub(crate) d: asn1::BigUint<'a>,
    pub(crate) p: asn1::BigUint<'a>,
    pub(crate) q: asn1::BigUint<'a>,
    pub(crate) dmp1: asn1::BigUint<'a>,
    pub(crate) dmq1: asn1::BigUint<'a>,
    pub(crate) iqmp: asn1::BigUint<'a>,
    // We don't support these, so don't bother to parse the inner fields.
    pub(crate) other_prime_infos: Option<asn1::SequenceOf<'a, asn1::Sequence<'a>, 1>>,
}

/// Parses a PKCS #1 RSA private key, rejecting multi-prime keys and versions
/// other than 0.
pub(crate) fn parse_rsa_private_key(data: &[u8]) -> KeyParsingResult<RsaPrivateKey<'_>> {
    let key = asn1::parse_single::<RsaPrivateKey<'_>>(data)?;
    if key.version != 0 || key.other_prime_infos.is_some() {
        return Err(KeyParsingError::InvalidKey);
    }
    Ok(key)
}

// OpenSSL's traditional DSA private key format.
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct DsaPrivateKey<'a> {
    pub(crate) version: u8,
    pub(crate) p: asn1::BigUint<'a>,
    pub(crate) q: asn1::BigUint<'a>,
    pub(crate) g: asn1::BigUint<'a>,
    pub(crate) pub_key: asn1::BigUint<'a>,
    pub(crate) priv_key: asn1::BigUint<'a>,
}

/// Parses an OpenSSL traditional DSA private key, rejecting versions other
/// than 0.
pub(crate) fn parse_dsa_private_key(data: &[u8]) -> KeyParsingResult<DsaPrivateKey<'_>> {
    let key = asn1::parse_single::<DsaPrivateKey<'_>>(data)?;
    if key.version != 0 {
        return Err(KeyParsingError::InvalidKey);
    }
    Ok(key)
}

// From RFC 5915 Section 3
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct EcPrivateKey<'a> {
    pub(crate) version: u8,
    pub(crate) private_key: &'a [u8],
    #[explicit(0)]
    pub(crate) parameters: Option<EcParameters<'a>>,
    #[explicit(1)]
    pub(crate) public_key: Option<asn1::BitString<'a>>,
}

/// Parses an RFC 5915 EC private key, rejecting versions other than 1, and
/// returns it with the curve parameters: those given (from a PKCS #8
/// wrapper) or the key's own, which must agree when both are present.
pub(crate) fn parse_ec_private_key<'a>(
    data: &'a [u8],
    ec_params: Option<EcParameters<'a>>,
) -> KeyParsingResult<(EcPrivateKey<'a>, EcParameters<'a>)> {
    let key = asn1::parse_single::<EcPrivateKey<'_>>(data)?;
    if key.version != 1 {
        return Err(KeyParsingError::InvalidKey);
    }
    let params = match (ec_params, &key.parameters) {
        (Some(outer_params), Some(inner_params)) => {
            if outer_params != *inner_params {
                return Err(KeyParsingError::InvalidKey);
            }
            outer_params
        }
        (Some(outer_params), None) => outer_params,
        (None, Some(inner_params)) => inner_params.clone(),
        (None, None) => return Err(KeyParsingError::InvalidKey),
    };
    Ok((key, params))
}

/// The OID of the named curve that EC parameters denote. Named curves map to
/// their OID, whether or not it is supported. We do not support arbitrary
/// explicit curves: their parameters are mapped to the named curve they
/// equal. This currently supports only P256, P384, and P521. No binary
/// curves are supported. Everything must match, except the seed may be
/// omitted on NIST curves since OpenSSL has supported a -no_seed option for
/// over 20 years and I don't want to figure out whether anyone uses that or
/// not. No one should be using explicit curve encoding anyway. Curves were
/// meant to be named!
pub(crate) fn ec_params_to_curve_oid(
    params: &EcParameters<'_>,
) -> KeyParsingResult<asn1::ObjectIdentifier> {
    match params {
        EcParameters::NamedCurve(curve_oid) => Ok(curve_oid.clone()),
        EcParameters::SpecifiedCurve(params) => match params {
            &ec_constants::P256_DOMAIN | &ec_constants::P256_DOMAIN_NO_SEED => {
                Ok(cryptography_x509::oid::EC_SECP256R1)
            }
            &ec_constants::P384_DOMAIN | &ec_constants::P384_DOMAIN_NO_SEED => {
                Ok(cryptography_x509::oid::EC_SECP384R1)
            }
            &ec_constants::P521_DOMAIN | &ec_constants::P521_DOMAIN_NO_SEED => {
                Ok(cryptography_x509::oid::EC_SECP521R1)
            }
            _ => Err(KeyParsingError::ExplicitCurveUnsupported),
        },
        EcParameters::ImplicitCurve(_) => Err(KeyParsingError::ExplicitCurveUnsupported),
    }
}

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

pub(crate) const PKCS8_VERSION_V1: u8 = 0;
pub(crate) const PKCS8_VERSION_V2: u8 = 1;

/// Parses a PKCS #8 `PrivateKeyInfo` (or RFC 5958 `OneAsymmetricKey`).
pub(crate) fn parse_private_key_info(data: &[u8]) -> KeyParsingResult<PrivateKeyInfo<'_>> {
    let k = asn1::parse_single::<PrivateKeyInfo<'_>>(data)?;
    // RFC 5958 Section 2: v1 is used for keys with no public key, v2 is used
    // when a public key is present (but the public key remains optional).
    match (k.version, &k.public_key) {
        (PKCS8_VERSION_V1, None) | (PKCS8_VERSION_V2, _) => Ok(k),
        _ => Err(KeyParsingError::InvalidKey),
    }
}

// RFC 9935 Section 6
#[cfg(any(
    feature = "verified-garbage",
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
    feature = "verified-garbage",
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC,
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
))]
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum MlDsaPrivateKey {
    #[implicit(0)]
    Seed([u8; 32]),
}

/// The iteration count of the KDF when encrypting PKCS #8 keys.
pub(crate) const KDF_ITERATION_COUNT: u64 = 2048;
