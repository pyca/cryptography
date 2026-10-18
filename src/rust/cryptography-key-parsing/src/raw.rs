// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Keys as their raw components, for backends (verified-garbage) that do not
//! parse keys themselves. Parsing checks only the encoding: the backend
//! validates the components (e.g. that an RSA key's primes multiply to its
//! modulus) when it builds its key objects from them.
//!
//! Integers are unsigned and big-endian, without leading zeros (as
//! `asn1::BigUint` holds them).

/// An RSA public key (`RSAPublicKey`, RFC 8017).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPublicKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

/// A two-prime RSA private key (`RSAPrivateKey`, RFC 8017). Multi-prime
/// keys are rejected when parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPrivateKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub d: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub dmp1: Vec<u8>,
    pub dmq1: Vec<u8>,
    pub iqmp: Vec<u8>,
}

/// An elliptic curve, by its named-curve OID (explicit curves are rejected
/// when parsing, as with OpenSSL).
pub type EcCurve = asn1::ObjectIdentifier;

/// An EC public key: its curve and its point, encoded as in SEC 1 §2.3.3
/// (uncompressed, compressed or hybrid, as it was found).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcPublicKey {
    pub curve: EcCurve,
    pub point: Vec<u8>,
}

/// An EC private key (`ECPrivateKey`, RFC 5915): its curve, its scalar
/// (big-endian, as encoded: the backend checks its range), and the public
/// point if the encoding includes it (the backend derives it otherwise, and
/// should check that an included one matches).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcPrivateKey {
    pub curve: EcCurve,
    pub private_value: Vec<u8>,
    pub public_point: Option<Vec<u8>>,
}

/// DSA domain parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsaParameters {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub g: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsaPublicKey {
    pub params: DsaParameters,
    pub y: Vec<u8>,
}

/// A DSA private key. PKCS #8 does not carry `y`, so parsing it leaves `y`
/// `None`; the backend computes `y = g^x mod p` (and checks a parsed `y`
/// against it). Serializing to OpenSSL's traditional format needs `y`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsaPrivateKey {
    pub params: DsaParameters,
    pub x: Vec<u8>,
    pub y: Option<Vec<u8>>,
}

/// Diffie–Hellman domain parameters; `q` is present for X9.42 (`dhpublicnumber`)
/// parameters, absent for PKCS #3 (`dhKeyAgreement`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhParameters {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
    pub q: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhPublicKey {
    pub params: DhParameters,
    pub y: Vec<u8>,
}

/// A DH private key; the backend computes `y` (`g^x mod p`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhPrivateKey {
    pub params: DhParameters,
    pub x: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Rsa(RsaPublicKey),
    /// An `id-RSASSA-PSS` key (the parameters' restrictions are dropped, as
    /// cryptography does with OpenSSL).
    RsaPss(RsaPublicKey),
    Ec(EcPublicKey),
    Dsa(DsaPublicKey),
    Dh(DhPublicKey),
    X25519([u8; 32]),
    X448([u8; 56]),
    Ed25519([u8; 32]),
    Ed448([u8; 57]),
    /// Encapsulation keys (1184 and 1568 bytes).
    MlKem768(Vec<u8>),
    MlKem1024(Vec<u8>),
    /// Verification keys (1312, 1952 and 2592 bytes).
    MlDsa44(Vec<u8>),
    MlDsa65(Vec<u8>),
    MlDsa87(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateKey {
    Rsa(RsaPrivateKey),
    RsaPss(RsaPrivateKey),
    Ec(EcPrivateKey),
    Dsa(DsaPrivateKey),
    Dh(DhPrivateKey),
    X25519([u8; 32]),
    X448([u8; 56]),
    Ed25519([u8; 32]),
    Ed448([u8; 57]),
    /// ML-KEM keys as their 64-byte seed (`d || z`), the only private key
    /// form cryptography supports.
    MlKem768([u8; 64]),
    MlKem1024([u8; 64]),
    /// ML-DSA keys as their 32-byte seed (`xi`).
    MlDsa44([u8; 32]),
    MlDsa65([u8; 32]),
    MlDsa87([u8; 32]),
}
