// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Elliptic curve keys (ECDSA and ECDH) on verified-garbage.
//!
//! The curves are those verified-garbage implements: P-192, P-224, P-256,
//! P-384, P-521, secp256k1 and brainpoolP256r1/P384r1/P512r1 (all of
//! cofactor 1). Keys hold their components (the scalar at the curve's
//! width and the uncompressed public point), from which each operation
//! builds verified-garbage's key types.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use cryptography_key_parsing::raw;
use cryptography_x509::common::DssSignature;
use pyo3::types::PyAnyMethods;
use verified_garbage::ecdsa;
use verified_garbage::hashes::sha224::Sha224;
use verified_garbage::hashes::sha256::Sha256;
use verified_garbage::hashes::sha384::Sha384;
use verified_garbage::hashes::sha512::Sha512;
use verified_garbage::hashes::HashFunction;

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

/// Overwrites a buffer that held secret bytes.
pub(crate) fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    std::hint::black_box(&buf);
}

/// A secret byte string, wiped when dropped.
pub(crate) struct SecretBytes(pub(crate) Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// `b` without its leading zero bytes.
pub(crate) fn trim_zeros(b: &[u8]) -> &[u8] {
    let z = b.iter().take_while(|&&x| x == 0).count();
    &b[z..]
}

/// The unsigned big-endian `b` left-padded with zeros to `len` bytes, if
/// its value fits.
pub(crate) fn left_pad(b: &[u8], len: usize) -> Option<Vec<u8>> {
    let b = trim_zeros(b);
    if b.len() > len {
        return None;
    }
    let mut out = vec![0; len - b.len()];
    out.extend_from_slice(b);
    Some(out)
}

/// The DER `Dss-Sig-Value` (`SEQUENCE { r, s }`) of a fixed-width `r || s`.
pub(crate) fn der_signature(rs: &[u8]) -> CryptographyResult<Vec<u8>> {
    fn uint(v: &[u8]) -> Vec<u8> {
        let v = trim_zeros(v);
        let mut out = Vec::with_capacity(v.len() + 1);
        if v.first().is_none_or(|&b| b & 0x80 != 0) {
            out.push(0);
        }
        out.extend_from_slice(v);
        out
    }
    let (r, s) = rs.split_at(rs.len() / 2);
    let (r, s) = (uint(r), uint(s));
    let sig = DssSignature {
        r: asn1::BigUint::new(&r).unwrap(),
        s: asn1::BigUint::new(&s).unwrap(),
    };
    Ok(asn1::write_single(&sig)?)
}

/// The fixed-width `r || s` (each `width` bytes) of a DER `Dss-Sig-Value`,
/// if it parses and both values fit.
pub(crate) fn parse_der_signature(der: &[u8], width: usize) -> Option<Vec<u8>> {
    let sig = asn1::parse_single::<DssSignature<'_>>(der).ok()?;
    let mut out = left_pad(sig.r.as_bytes(), width)?;
    out.extend(left_pad(sig.s.as_bytes(), width)?);
    Some(out)
}

/// A curve verified-garbage implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Curve {
    P192,
    P224,
    P256,
    P384,
    P521,
    Secp256k1,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
}

const CURVES: [Curve; 9] = [
    Curve::P192,
    Curve::P224,
    Curve::P256,
    Curve::P384,
    Curve::P521,
    Curve::Secp256k1,
    Curve::BrainpoolP256r1,
    Curve::BrainpoolP384r1,
    Curve::BrainpoolP512r1,
];

impl Curve {
    fn from_name(name: &str) -> Option<Curve> {
        match name {
            "prime192v1" => Some(Curve::P192),
            "prime256v1" => Some(Curve::P256),
            _ => CURVES.into_iter().find(|c| c.name() == name),
        }
    }

    fn from_oid(oid: &asn1::ObjectIdentifier) -> Option<Curve> {
        CURVES.into_iter().find(|c| &c.oid() == oid)
    }

    /// The curve's name in cryptography (`EllipticCurve.name`).
    fn name(self) -> &'static str {
        match self {
            Curve::P192 => "secp192r1",
            Curve::P224 => "secp224r1",
            Curve::P256 => "secp256r1",
            Curve::P384 => "secp384r1",
            Curve::P521 => "secp521r1",
            Curve::Secp256k1 => "secp256k1",
            Curve::BrainpoolP256r1 => "brainpoolP256r1",
            Curve::BrainpoolP384r1 => "brainpoolP384r1",
            Curve::BrainpoolP512r1 => "brainpoolP512r1",
        }
    }

    fn oid(self) -> asn1::ObjectIdentifier {
        use cryptography_x509::oid;
        match self {
            Curve::P192 => oid::EC_SECP192R1,
            Curve::P224 => oid::EC_SECP224R1,
            Curve::P256 => oid::EC_SECP256R1,
            Curve::P384 => oid::EC_SECP384R1,
            Curve::P521 => oid::EC_SECP521R1,
            Curve::Secp256k1 => oid::EC_SECP256K1,
            Curve::BrainpoolP256r1 => oid::EC_BRAINPOOLP256R1,
            Curve::BrainpoolP384r1 => oid::EC_BRAINPOOLP384R1,
            Curve::BrainpoolP512r1 => oid::EC_BRAINPOOLP512R1,
        }
    }

    /// The length in bytes of a field element and of a scalar (they are
    /// the same on every curve here).
    fn len(self) -> usize {
        match self {
            Curve::P192 => 24,
            Curve::P224 => 28,
            Curve::P256 | Curve::Secp256k1 | Curve::BrainpoolP256r1 => 32,
            Curve::P384 | Curve::BrainpoolP384r1 => 48,
            Curve::P521 => 66,
            Curve::BrainpoolP512r1 => 64,
        }
    }

    /// The bit length of the group's order.
    fn order_bits(self) -> usize {
        match self {
            Curve::P521 => 521,
            c => 8 * c.len(),
        }
    }

    fn unsupported(name: impl std::fmt::Display) -> CryptographyError {
        CryptographyError::from(exceptions::UnsupportedAlgorithm::new_err((
            format!("Curve {name} is not supported"),
            exceptions::Reasons::UNSUPPORTED_ELLIPTIC_CURVE,
        )))
    }
}

/// Runs `$body` with `$c` naming the verified-garbage curve type of
/// `$curve` and `$h` the hash function its ECDSA signs with (the one whose
/// output is at least as long as the order, or P-521's SHA-512).
macro_rules! with_curve {
    ($curve:expr, $c:ident, $h:ident, $body:block) => {
        match $curve {
            Curve::P192 => {
                #[allow(dead_code)]
                type $c = ecdsa::P192;
                #[allow(dead_code)]
                type $h = Sha256;
                $body
            }
            Curve::P224 => {
                #[allow(dead_code)]
                type $c = ecdsa::P224;
                #[allow(dead_code)]
                type $h = Sha224;
                $body
            }
            Curve::P256 => {
                #[allow(dead_code)]
                type $c = ecdsa::P256;
                #[allow(dead_code)]
                type $h = Sha256;
                $body
            }
            Curve::P384 => {
                #[allow(dead_code)]
                type $c = ecdsa::P384;
                #[allow(dead_code)]
                type $h = Sha384;
                $body
            }
            Curve::P521 => {
                #[allow(dead_code)]
                type $c = ecdsa::P521;
                #[allow(dead_code)]
                type $h = Sha512;
                $body
            }
            Curve::Secp256k1 => {
                #[allow(dead_code)]
                type $c = ecdsa::Secp256k1;
                #[allow(dead_code)]
                type $h = Sha256;
                $body
            }
            Curve::BrainpoolP256r1 => {
                #[allow(dead_code)]
                type $c = ecdsa::BrainpoolP256r1;
                #[allow(dead_code)]
                type $h = Sha256;
                $body
            }
            Curve::BrainpoolP384r1 => {
                #[allow(dead_code)]
                type $c = ecdsa::BrainpoolP384r1;
                #[allow(dead_code)]
                type $h = Sha384;
                $body
            }
            Curve::BrainpoolP512r1 => {
                #[allow(dead_code)]
                type $c = ecdsa::BrainpoolP512r1;
                #[allow(dead_code)]
                type $h = Sha512;
                $body
            }
        }
    };
}

/// The public point `dG` (uncompressed) of the scalar `d` (`curve.len()`
/// bytes), if `d` is in `[1, n - 1]`.
fn public_point(curve: Curve, d: &[u8]) -> Option<Vec<u8>> {
    with_curve!(curve, C, H, {
        let mut d_arr: <C as ecdsa::Curve>::PrivateKey = d.try_into().ok()?;
        let key = ecdsa::SigningKey::<C>::from_bytes(&d_arr);
        wipe(&mut d_arr);
        key.public_key().ok().map(|q| q.to_vec())
    })
}

/// Whether `point` is a valid uncompressed public point on `curve`: both
/// coordinates below `p` and on the curve (SP 800-56A §5.6.2.3.3; with a
/// cofactor of 1 this is full validation). verified-garbage validates the
/// peer's point in every ECDH exchange, so this is an exchange with the
/// (public) scalar 1, whose result is discarded.
fn point_valid(curve: Curve, point: &[u8]) -> bool {
    with_curve!(curve, C, H, {
        let Ok(q) = <<C as ecdsa::Curve>::PublicKey>::try_from(point) else {
            return false;
        };
        let mut one = vec![0; curve.len()];
        one[curve.len() - 1] = 1;
        let one: <C as ecdsa::Curve>::PrivateKey = one.as_slice().try_into().unwrap();
        verified_garbage::ecdh::PrivateKey::<C>::from_bytes(&one)
            .diffie_hellman(&q)
            .is_ok()
    })
}

/// The ECDH shared secret (the x-coordinate of `d Q`) of the scalar `d`
/// and the (already validated) point `peer`.
fn exchange(curve: Curve, d: &[u8], peer: &[u8]) -> Option<Vec<u8>> {
    with_curve!(curve, C, H, {
        let mut d_arr: <C as ecdsa::Curve>::PrivateKey = d.try_into().ok()?;
        let key = verified_garbage::ecdh::PrivateKey::<C>::from_bytes(&d_arr);
        wipe(&mut d_arr);
        let q: <C as ecdsa::Curve>::PublicKey = peer.try_into().ok()?;
        key.diffie_hellman(&q).ok().map(|z| z.to_vec())
    })
}

/// A hash value of `H` whose leftmost bits, as ECDSA over a curve of an
/// order of `order_bits` bits reads them (FIPS 186-5 §6.4.1, `bits2int`),
/// are the same integer as those of `digest`, a hash value of another hash
/// function: so that signing or verifying it with `H` signs or verifies
/// `digest`. `None` if no such value exists (a digest longer than P-521's
/// SHA-512 one).
///
/// This only re-encodes `digest`: for an order of `8 q` bits the integer is
/// `digest`'s leftmost `q` bytes, left-padded to `q` bytes and followed by
/// zeros (`H` is at least `q` bytes long); for P-521, whose SHA-512 values
/// are shorter than the order, it is `digest` left-padded to `H`'s length.
fn ecdsa_input(digest: &[u8], order_bits: usize, h_len: usize) -> Option<Vec<u8>> {
    if order_bits % 8 == 0 && 8 * h_len >= order_bits {
        let q = order_bits / 8;
        let e = &digest[..digest.len().min(q)];
        let mut out = vec![0; q - e.len()];
        out.extend_from_slice(e);
        out.resize(h_len, 0);
        Some(out)
    } else if 8 * h_len <= order_bits && digest.len() <= h_len {
        let mut out = vec![0; h_len - digest.len()];
        out.extend_from_slice(digest);
        Some(out)
    } else {
        None
    }
}

/// Signs the hash value `x` of `H` with `d`: the signature `r || s`.
fn sign_with<C, H>(d: &[u8], x: &[u8]) -> Option<Vec<u8>>
where
    C: ecdsa::Curve,
    H: ecdsa::SignatureHash<C>,
    for<'a> C::PrivateKey: TryFrom<&'a [u8]>,
    for<'a> H::Output: TryFrom<&'a [u8]>,
    C::Signature: AsRef<[u8]>,
{
    let mut d_arr = C::PrivateKey::try_from(d).ok()?;
    let key = ecdsa::SigningKey::<C>::from_bytes(&d_arr);
    wipe(d_arr.as_mut());
    let x = H::Output::try_from(x).ok()?;
    key.sign_prehashed::<H>(&x)
        .ok()
        .map(|s| s.as_ref().to_vec())
}

/// Whether `rs` (`r || s`) is a signature of the hash value `x` of `H` with
/// the public point `q`.
fn verify_with<C, H>(q: &[u8], x: &[u8], rs: &[u8]) -> bool
where
    C: ecdsa::Curve,
    H: ecdsa::SignatureHash<C>,
    for<'a> C::PublicKey: TryFrom<&'a [u8]>,
    for<'a> H::Output: TryFrom<&'a [u8]>,
    for<'a> C::Signature: TryFrom<&'a [u8]>,
{
    let (Ok(q), Ok(x), Ok(rs)) = (
        C::PublicKey::try_from(q),
        H::Output::try_from(x),
        C::Signature::try_from(rs),
    ) else {
        return false;
    };
    ecdsa::VerifyingKey::<C>::from_bytes(&q)
        .verify_prehashed::<H>(&x, &rs)
        .is_ok()
}

/// The ECDSA signature (`r || s`) of `digest`, a hash value of the hash
/// function named `hash_name`. With the hash function verified-garbage
/// signs with on the curve (and P-256's SHA-384), this is the deterministic
/// signature of RFC 6979; otherwise the digest is re-encoded
/// (`ecdsa_input`) and signed with that hash function, whose RFC 6979
/// derivation of `k` then reads the re-encoded value. `None` if the digest
/// cannot be signed on this curve (`ecdsa_input`) or `d` is not valid.
fn ecdsa_sign(
    curve: Curve,
    d: &[u8],
    digest: &[u8],
    hash_name: &str,
    deterministic: bool,
) -> CryptographyResult<Vec<u8>> {
    let unsupported = || {
        CryptographyError::from(exceptions::UnsupportedAlgorithm::new_err((
            format!(
                "ECDSA with {hash_name} on {} is not supported by this backend",
                curve.name()
            ),
            exceptions::Reasons::UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
        )))
    };
    if curve == Curve::P256 && hash_name == "sha384" && digest.len() == 48 {
        return sign_with::<ecdsa::P256, Sha384>(d, digest)
            .ok_or(CryptographyError::VerifiedGarbage("ECDSA signing failed"));
    }
    with_curve!(curve, C, H, {
        let native = H::OUTPUT_SIZE == digest.len()
            && hash_name
                == match H::OUTPUT_SIZE {
                    28 => "sha224",
                    32 => "sha256",
                    48 => "sha384",
                    _ => "sha512",
                };
        if deterministic && !native {
            return Err(unsupported());
        }
        let x = if native {
            digest.to_vec()
        } else {
            ecdsa_input(digest, curve.order_bits(), H::OUTPUT_SIZE).ok_or_else(unsupported)?
        };
        sign_with::<C, H>(d, &x).ok_or(CryptographyError::VerifiedGarbage("ECDSA signing failed"))
    })
}

/// Whether `rs` (`r || s`) is an ECDSA signature of `digest` with the
/// public point `q`. (Verification reads only the digest's leftmost bits,
/// so any hash function's value is verified as `ecdsa_input` re-encodes
/// it.)
fn ecdsa_verify(curve: Curve, q: &[u8], digest: &[u8], rs: &[u8]) -> bool {
    with_curve!(curve, C, H, {
        match ecdsa_input(digest, curve.order_bits(), H::OUTPUT_SIZE) {
            Some(x) => verify_with::<C, H>(q, &x, rs),
            None => false,
        }
    })
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ec")]
pub(crate) struct ECPrivateKey {
    kind: Curve,
    /// The scalar `d`, `kind.len()` bytes.
    d: SecretBytes,
    /// The public point, uncompressed.
    point: Vec<u8>,
    #[pyo3(get)]
    curve: pyo3::Py<pyo3::PyAny>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ec")]
pub(crate) struct ECPublicKey {
    kind: Curve,
    /// The public point, uncompressed and validated.
    point: Vec<u8>,
    #[pyo3(get)]
    curve: pyo3::Py<pyo3::PyAny>,
}

fn curve_from_py_curve(
    py: pyo3::Python<'_>,
    py_curve: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Curve> {
    if !py_curve.is_instance(&types::ELLIPTIC_CURVE.get(py)?)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err("curve must be an EllipticCurve instance"),
        ));
    }

    let py_curve_name = py_curve.getattr(pyo3::intern!(py, "name"))?;
    let curve_name = &*py_curve_name.extract::<pyo3::pybacked::PyBackedStr>()?;
    Curve::from_name(curve_name).ok_or_else(|| Curve::unsupported(curve_name))
}

fn py_curve_from_curve(
    py: pyo3::Python<'_>,
    curve: Curve,
) -> CryptographyResult<pyo3::Bound<'_, pyo3::PyAny>> {
    Ok(types::CURVE_TYPES.get(py)?.get_item(curve.name())?)
}

fn infinity_error() -> CryptographyError {
    CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
        "Cannot load an EC public key where the point is at infinity",
    ))
}

/// The uncompressed form of an encoded point, validated on `curve`.
/// Compressed points need a square root modulo `p`, which verified-garbage
/// does not expose: they are refused as unsupported.
fn uncompressed_point(curve: Curve, data: &[u8]) -> CryptographyResult<Vec<u8>> {
    let invalid = || pyo3::exceptions::PyValueError::new_err("Invalid EC key.");
    let n = curve.len();
    let point = match data.first() {
        Some(0) if data.len() == 1 => return Err(infinity_error()),
        Some(4) => data.to_vec(),
        // The hybrid form: the uncompressed point with the parity of `y` in
        // its first byte.
        Some(6 | 7) if data.len() == 1 + 2 * n => {
            if data[0] & 1 != data[data.len() - 1] & 1 {
                return Err(CryptographyError::from(invalid()));
            }
            let mut point = data.to_vec();
            point[0] = 4;
            point
        }
        Some(2 | 3) if data.len() == 1 + n => {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Compressed elliptic curve points are not supported by this backend",
                    exceptions::Reasons::UNSUPPORTED_ELLIPTIC_CURVE,
                )),
            ));
        }
        _ => return Err(CryptographyError::from(invalid())),
    };
    if point.len() != 1 + 2 * n || !point_valid(curve, &point) {
        return Err(CryptographyError::from(invalid()));
    }
    Ok(point)
}

#[pyo3::pyfunction]
fn curve_supported(py: pyo3::Python<'_>, py_curve: pyo3::Bound<'_, pyo3::PyAny>) -> bool {
    curve_from_py_curve(py, &py_curve).is_ok()
}

impl ECPrivateKey {
    /// The key of the scalar `d` (any number of leading zero bytes), or
    /// `None` if it is not in `[1, n - 1]`.
    fn from_scalar(curve: Curve, d: &[u8], py_curve: pyo3::Py<pyo3::PyAny>) -> Option<Self> {
        let d = SecretBytes(left_pad(d, curve.len())?);
        let point = public_point(curve, &d.0)?;
        Some(ECPrivateKey {
            kind: curve,
            d,
            point,
            curve: py_curve,
        })
    }

    fn raw(&self) -> raw::PrivateKey {
        raw::PrivateKey::Ec(raw::EcPrivateKey {
            curve: self.kind.oid(),
            private_value: self.d.0.clone(),
            public_point: Some(self.point.clone()),
        })
    }
}

impl ECPublicKey {
    fn raw(&self) -> raw::PublicKey {
        raw::PublicKey::Ec(raw::EcPublicKey {
            curve: self.kind.oid(),
            point: self.point.clone(),
        })
    }
}

/// The key object of a parsed EC private key: checks that the scalar is in
/// `[1, n - 1]`, derives the public point, and checks that an encoded
/// public point is that one (in whichever form it was encoded).
pub(crate) fn private_key_from_raw(
    py: pyo3::Python<'_>,
    key: &raw::EcPrivateKey,
) -> CryptographyResult<ECPrivateKey> {
    let curve = Curve::from_oid(&key.curve).ok_or_else(|| Curve::unsupported(&key.curve))?;
    let py_curve = py_curve_from_curve(py, curve)?.unbind();
    let private_key = ECPrivateKey::from_scalar(curve, &key.private_value, py_curve)
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(
                "Invalid key: the EC private value must be in [1, n - 1] (its public point would be the point at infinity or undefined)",
            )
        })?;
    if let Some(encoded) = &key.public_point {
        if encoded.as_slice() == [0] {
            return Err(infinity_error());
        }
        let ours = &private_key.point;
        let matches = match encoded.first() {
            Some(4) => encoded == ours,
            Some(2 | 3) => *encoded == utils::compress_ec_point(ours),
            Some(6 | 7) => encoded[1..] == ours[1..] && encoded[0] & 1 == ours[ours.len() - 1] & 1,
            _ => false,
        };
        if !matches {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Invalid EC key"),
            ));
        }
    }
    Ok(private_key)
}

/// The key object of a parsed EC public key, whose point is validated.
pub(crate) fn public_key_from_raw(
    py: pyo3::Python<'_>,
    key: &raw::EcPublicKey,
) -> CryptographyResult<ECPublicKey> {
    let curve = Curve::from_oid(&key.curve).ok_or_else(|| Curve::unsupported(&key.curve))?;
    let point = uncompressed_point(curve, &key.point)?;
    Ok(ECPublicKey {
        kind: curve,
        point,
        curve: py_curve_from_curve(py, curve)?.unbind(),
    })
}

#[pyo3::pyfunction]
#[pyo3(signature = (curve, backend=None))]
pub(crate) fn generate_private_key(
    py: pyo3::Python<'_>,
    curve: pyo3::Bound<'_, pyo3::PyAny>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<ECPrivateKey> {
    let _ = backend;

    let kind = curve_from_py_curve(py, &curve)?;
    let py_curve = py_curve_from_curve(py, kind)?.unbind();
    // Rejection sampling of a uniform scalar in [1, n - 1]: random bytes
    // with the order's bit length, until verified-garbage accepts one as a
    // private key (it refuses 0 and values not below n). Every curve's order
    // is above half of 2^bits, so each draw is accepted with probability
    // above 1/2.
    let mut d = SecretBytes(vec![0; kind.len()]);
    let excess_bits = 8 * kind.len() - kind.order_bits();
    for _ in 0..128 {
        getrandom::fill(&mut d.0)
            .map_err(|_| CryptographyError::VerifiedGarbage("random number generator failed"))?;
        d.0[0] &= 0xff >> excess_bits;
        if let Some(key) = ECPrivateKey::from_scalar(kind, &d.0, py_curve.clone_ref(py)) {
            return Ok(key);
        }
    }
    Err(CryptographyError::VerifiedGarbage(
        "EC key generation exhausted its attempts",
    ))
}

#[pyo3::pyfunction]
fn derive_private_key(
    py: pyo3::Python<'_>,
    py_private_value: &pyo3::Bound<'_, pyo3::types::PyInt>,
    py_curve: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<ECPrivateKey> {
    let curve = curve_from_py_curve(py, &py_curve)?;
    let private_value = SecretBytes(utils::py_int_to_be_bytes(py, py_private_value)?);
    ECPrivateKey::from_scalar(curve, &private_value.0, py_curve.unbind()).ok_or_else(|| {
        CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
            "Invalid EC key (key out of range, infinity, etc.)",
        ))
    })
}

#[pyo3::pyfunction]
pub(crate) fn from_public_bytes(
    py: pyo3::Python<'_>,
    py_curve: pyo3::Bound<'_, pyo3::PyAny>,
    data: &[u8],
) -> CryptographyResult<ECPublicKey> {
    let curve = curve_from_py_curve(py, &py_curve)?;
    let point = uncompressed_point(curve, data)?;
    Ok(ECPublicKey {
        kind: curve,
        point,
        curve: py_curve.unbind(),
    })
}

/// The affine coordinates of an uncompressed point, as Python ints.
fn point_numbers(
    py: pyo3::Python<'_>,
    point: &[u8],
    curve: &pyo3::Py<pyo3::PyAny>,
) -> CryptographyResult<EllipticCurvePublicNumbers> {
    let (x, y) = point[1..].split_at((point.len() - 1) / 2);
    Ok(EllipticCurvePublicNumbers {
        x: utils::be_bytes_to_py_int(py, x)?.extract()?,
        y: utils::be_bytes_to_py_int(py, y)?.extract()?,
        curve: curve.clone_ref(py),
    })
}

#[pyo3::pymethods]
impl ECPrivateKey {
    #[getter]
    fn key_size<'p>(
        &'p self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        self.curve.bind(py).getattr(pyo3::intern!(py, "key_size"))
    }

    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
        peer_public_key: &ECPublicKey,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if !algorithm.is_instance(&types::ECDH.get(py)?)? {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Unsupported EC exchange algorithm",
                    exceptions::Reasons::UNSUPPORTED_EXCHANGE_ALGORITHM,
                )),
            ));
        }
        if peer_public_key.kind != self.kind {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Error computing shared key."),
            ));
        }

        let mut z = exchange(self.kind, &self.d.0, &peer_public_key.point)
            .ok_or(CryptographyError::VerifiedGarbage("ECDH exchange failed"))?;
        let result = pyo3::types::PyBytes::new(py, &z);
        wipe(&mut z);
        Ok(result)
    }

    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        signature_algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if !signature_algorithm.is_instance(&types::ECDSA.get(py)?)? {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Unsupported elliptic curve signature algorithm",
                    exceptions::Reasons::UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
                )),
            ));
        }
        let bound_algorithm = signature_algorithm.getattr(pyo3::intern!(py, "algorithm"))?;
        let (data, algo) =
            utils::calculate_digest_and_algorithm(py, data.as_bytes(), &bound_algorithm)?;
        let deterministic: bool = signature_algorithm
            .getattr(pyo3::intern!(py, "deterministic_signing"))?
            .extract()?;
        let hash_name = algo
            .getattr(pyo3::intern!(py, "name"))?
            .extract::<pyo3::pybacked::PyBackedStr>()?;

        let rs = ecdsa_sign(
            self.kind,
            &self.d.0,
            data.as_bytes(),
            &hash_name,
            deterministic,
        )?;
        Ok(pyo3::types::PyBytes::new(py, &der_signature(&rs)?))
    }

    fn public_key(&self, py: pyo3::Python<'_>) -> ECPublicKey {
        ECPublicKey {
            kind: self.kind,
            point: self.point.clone(),
            curve: self.curve.clone_ref(py),
        }
    }

    fn private_numbers(
        &self,
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<EllipticCurvePrivateNumbers> {
        let public_numbers = point_numbers(py, &self.point, &self.curve)?;
        Ok(EllipticCurvePrivateNumbers {
            private_value: utils::be_bytes_to_py_int(py, &self.d.0)?.extract()?,
            public_numbers: pyo3::Py::new(py, public_numbers)?,
        })
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::raw_private_bytes(
            py,
            slf,
            &slf.get().raw(),
            encoding,
            format,
            encryption_algorithm,
            true,
            false,
        )
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymethods]
impl ECPublicKey {
    #[getter]
    fn key_size<'p>(
        &'p self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        self.curve.bind(py).getattr(pyo3::intern!(py, "key_size"))
    }

    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        signature_algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<()> {
        if !signature_algorithm.is_instance(&types::ECDSA.get(py)?)? {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Unsupported elliptic curve signature algorithm",
                    exceptions::Reasons::UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
                )),
            ));
        }

        let (data, _) = utils::calculate_digest_and_algorithm(
            py,
            data.as_bytes(),
            &signature_algorithm.getattr(pyo3::intern!(py, "algorithm"))?,
        )?;

        let valid = parse_der_signature(signature.as_bytes(), self.kind.len())
            .is_some_and(|rs| ecdsa_verify(self.kind, &self.point, data.as_bytes(), &rs));
        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    fn public_numbers(
        &self,
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<EllipticCurvePublicNumbers> {
        point_numbers(py, &self.point, &self.curve)
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::raw_public_bytes(py, slf, &slf.get().raw(), encoding, format, true, false)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.kind == other.kind && self.point == other.point
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.primitives.asymmetric.ec")]
struct EllipticCurvePrivateNumbers {
    #[pyo3(get)]
    private_value: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    public_numbers: pyo3::Py<EllipticCurvePublicNumbers>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.primitives.asymmetric.ec")]
struct EllipticCurvePublicNumbers {
    #[pyo3(get)]
    x: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    y: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    curve: pyo3::Py<pyo3::PyAny>,
}

/// The validated uncompressed point of public numbers.
fn point_from_numbers(
    py: pyo3::Python<'_>,
    numbers: &EllipticCurvePublicNumbers,
    curve: Curve,
) -> CryptographyResult<Vec<u8>> {
    if numbers.x.bind(py).lt(0)? || numbers.y.bind(py).lt(0)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "Invalid EC key. Both x and y must be non-negative.",
            ),
        ));
    }

    let not_on_curve = || {
        CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
            "Invalid EC key. Point is not on the curve specified.",
        ))
    };
    let x = utils::py_int_to_be_bytes(py, numbers.x.bind(py))?;
    let y = utils::py_int_to_be_bytes(py, numbers.y.bind(py))?;
    let mut point = vec![4];
    point.extend(left_pad(&x, curve.len()).ok_or_else(not_on_curve)?);
    point.extend(left_pad(&y, curve.len()).ok_or_else(not_on_curve)?);
    if !point_valid(curve, &point) {
        return Err(not_on_curve());
    }
    Ok(point)
}

#[pyo3::pymethods]
impl EllipticCurvePrivateNumbers {
    #[new]
    fn new(
        private_value: pyo3::Py<pyo3::types::PyInt>,
        public_numbers: pyo3::Py<EllipticCurvePublicNumbers>,
    ) -> EllipticCurvePrivateNumbers {
        EllipticCurvePrivateNumbers {
            private_value,
            public_numbers,
        }
    }

    #[pyo3(signature = (backend=None))]
    fn private_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<ECPrivateKey> {
        let _ = backend;

        let public_numbers = self.public_numbers.get();
        let curve = curve_from_py_curve(py, public_numbers.curve.bind(py))?;
        let point = point_from_numbers(py, public_numbers, curve)?;
        let invalid =
            || CryptographyError::from(pyo3::exceptions::PyValueError::new_err("Invalid EC key."));
        if self.private_value.bind(py).lt(0)? {
            return Err(invalid());
        }
        let private_value =
            SecretBytes(utils::py_int_to_be_bytes(py, self.private_value.bind(py))?);
        let key =
            ECPrivateKey::from_scalar(curve, &private_value.0, public_numbers.curve.clone_ref(py))
                .ok_or_else(invalid)?;
        if key.point != point {
            return Err(invalid());
        }
        Ok(key)
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok(
            (**self.private_value.bind(py)).eq(other.private_value.bind(py))?
                && self
                    .public_numbers
                    .bind(py)
                    .eq(other.public_numbers.bind(py))?,
        )
    }

    fn __hash__(&self, py: pyo3::Python<'_>) -> CryptographyResult<u64> {
        let mut hasher = DefaultHasher::new();
        self.private_value.bind(py).hash()?.hash(&mut hasher);
        self.public_numbers.bind(py).hash()?.hash(&mut hasher);
        Ok(hasher.finish())
    }
}

#[pyo3::pymethods]
impl EllipticCurvePublicNumbers {
    #[new]
    fn new(
        py: pyo3::Python<'_>,
        x: pyo3::Py<pyo3::types::PyInt>,
        y: pyo3::Py<pyo3::types::PyInt>,
        curve: pyo3::Py<pyo3::PyAny>,
    ) -> CryptographyResult<EllipticCurvePublicNumbers> {
        if !curve
            .bind(py)
            .is_instance(&types::ELLIPTIC_CURVE.get(py)?)?
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "curve must provide the EllipticCurve interface.",
                ),
            ));
        }

        Ok(EllipticCurvePublicNumbers { x, y, curve })
    }

    #[pyo3(signature = (backend=None))]
    fn public_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<ECPublicKey> {
        let _ = backend;

        let curve = curve_from_py_curve(py, self.curve.bind(py))?;
        let point = point_from_numbers(py, self, curve)?;
        Ok(ECPublicKey {
            kind: curve,
            point,
            curve: self.curve.clone_ref(py),
        })
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok((**self.x.bind(py)).eq(other.x.bind(py))?
            && (**self.y.bind(py)).eq(other.y.bind(py))?
            && self
                .curve
                .bind(py)
                .getattr(pyo3::intern!(py, "name"))?
                .eq(other.curve.bind(py).getattr(pyo3::intern!(py, "name"))?)?
            && self
                .curve
                .bind(py)
                .getattr(pyo3::intern!(py, "key_size"))?
                .eq(other
                    .curve
                    .bind(py)
                    .getattr(pyo3::intern!(py, "key_size"))?)?)
    }

    fn __hash__(&self, py: pyo3::Python<'_>) -> CryptographyResult<u64> {
        let mut hasher = DefaultHasher::new();
        self.x.bind(py).hash()?.hash(&mut hasher);
        self.y.bind(py).hash()?.hash(&mut hasher);
        self.curve
            .bind(py)
            .getattr(pyo3::intern!(py, "name"))?
            .hash()?
            .hash(&mut hasher);
        self.curve
            .bind(py)
            .getattr(pyo3::intern!(py, "key_size"))?
            .hash()?
            .hash(&mut hasher);
        Ok(hasher.finish())
    }

    fn __repr__<'py>(
        &self,
        py: pyo3::Python<'py>,
    ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::types::PyString>> {
        let x = self.x.bind(py);
        let y = self.y.bind(py);
        let curve_name = self.curve.bind(py).getattr(pyo3::intern!(py, "name"))?;
        pyo3::types::PyString::from_fmt(
            py,
            format_args!("<EllipticCurvePublicNumbers(curve={curve_name}, x={x}, y={y})>"),
        )
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod ec {
    #[pymodule_export]
    use super::{
        curve_supported, derive_private_key, from_public_bytes, generate_private_key, ECPrivateKey,
        ECPublicKey, EllipticCurvePrivateNumbers, EllipticCurvePublicNumbers,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads the `Key = value` records of a NIST CAVP response file.
    fn records(path: &str) -> Vec<(String, std::collections::HashMap<String, String>)> {
        let root = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/cryptography_vectors/"
        );
        let text = std::fs::read_to_string(format!("{root}{path}")).unwrap();
        let mut section = String::new();
        let mut out = vec![];
        let mut cur = std::collections::HashMap::new();
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                if !cur.is_empty() {
                    out.push((section.clone(), std::mem::take(&mut cur)));
                }
                section = line.trim_matches(|c| c == '[' || c == ']').to_string();
            } else if let Some((k, v)) = line.split_once(" = ") {
                if k == "Msg" && !cur.is_empty() {
                    out.push((section.clone(), std::mem::take(&mut cur)));
                }
                cur.insert(k.to_string(), v.to_string());
            }
        }
        if !cur.is_empty() {
            out.push((section, cur));
        }
        out
    }

    fn hex(s: &str) -> Vec<u8> {
        let s = if s.len() % 2 == 1 {
            format!("0{s}")
        } else {
            s.to_string()
        };
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn curve_of(name: &str) -> Option<Curve> {
        match name {
            "P-192" => Some(Curve::P192),
            "P-224" => Some(Curve::P224),
            "P-256" => Some(Curve::P256),
            "P-384" => Some(Curve::P384),
            "P-521" => Some(Curve::P521),
            _ => None,
        }
    }

    /// FIPS 186-3 SigGen vectors: the public point of each `d`, and the
    /// signatures (whose `k` is random, so not ours) verify, for every hash
    /// function, through `ecdsa_input`'s re-encoding.
    #[test]
    fn siggen_vectors_verify() {
        let mut checked = 0;
        for (section, r) in records("asymmetric/ECDSA/FIPS_186-3/SigGen.txt") {
            let (curve, hash) = section.split_once(',').unwrap();
            let Some(curve) = curve_of(curve) else {
                continue;
            };
            let md = cryptography_crypto::hash::MessageDigest::from_name(
                &hash.to_lowercase().replace("sha-", "sha"),
            )
            .unwrap();
            let digest = cryptography_crypto::hash::hash(md, &hex(&r["Msg"])).unwrap();
            let d = left_pad(&hex(&r["d"]), curve.len()).unwrap();
            let mut point = vec![4];
            point.extend(left_pad(&hex(&r["Qx"]), curve.len()).unwrap());
            point.extend(left_pad(&hex(&r["Qy"]), curve.len()).unwrap());
            assert_eq!(public_point(curve, &d).unwrap(), point);
            assert!(point_valid(curve, &point));
            let mut rs = left_pad(&hex(&r["R"]), curve.len()).unwrap();
            rs.extend(left_pad(&hex(&r["S"]), curve.len()).unwrap());
            assert!(ecdsa_verify(curve, &point, &digest, &rs), "{section}");
            // Our own signature of the digest verifies too.
            let name = hash.to_lowercase().replace("sha-", "sha");
            let ours = ecdsa_sign(curve, &d, &digest, &name, false)
                .unwrap_or_else(|_| panic!("{section}"));
            assert!(ecdsa_verify(curve, &point, &digest, &ours));
            let mut bad = digest.to_vec();
            bad[0] ^= 1;
            assert!(!ecdsa_verify(curve, &point, &bad, &ours));
            let mut bad_point = point.clone();
            let last = bad_point.len() - 1;
            bad_point[last] ^= 1;
            assert!(!point_valid(curve, &bad_point));
            checked += 1;
        }
        assert!(checked > 100);
    }

    /// The scalar of an unencrypted PKCS #8 EC private key.
    fn pkcs8_scalar(der: &[u8]) -> Vec<u8> {
        let info = asn1::parse_single::<asn1::Sequence<'_>>(der).unwrap();
        let inner = info
            .parse(|p| -> asn1::ParseResult<&[u8]> {
                p.read_element::<u64>()?;
                p.read_element::<asn1::Sequence<'_>>()?;
                p.read_element::<&[u8]>()
            })
            .unwrap();
        let key = asn1::parse_single::<asn1::Sequence<'_>>(inner).unwrap();
        key.parse(|p| -> asn1::ParseResult<Vec<u8>> {
            p.read_element::<u64>()?;
            let d = p.read_element::<&[u8]>()?.to_vec();
            while !p.is_empty() {
                p.read_element::<asn1::Tlv<'_>>()?;
            }
            Ok(d)
        })
        .unwrap()
    }

    /// RFC 6979's deterministic signatures (OpenSSL's test file): with the
    /// hash function verified-garbage signs with on the curve, ours are
    /// exactly them; with another, deterministic signing is refused.
    #[test]
    fn rfc6979_vectors() {
        use base64::Engine;
        let root = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/cryptography_vectors/asymmetric/ECDSA/RFC6979/evppkey_ecdsa_rfc6979.txt"
        );
        let text = std::fs::read_to_string(root).unwrap();
        let mut keys = std::collections::HashMap::new();
        let mut lines = text.lines().map(str::trim);
        let mut record = std::collections::HashMap::new();
        let (mut matched, mut refused) = (0, 0);
        while let Some(line) = lines.next() {
            if let Some(name) = line.strip_prefix("PrivateKey=") {
                let pem: String = lines
                    .by_ref()
                    .take_while(|l| !l.starts_with("-----END"))
                    .filter(|l| !l.starts_with("-----"))
                    .collect();
                let der = base64::engine::general_purpose::STANDARD
                    .decode(pem)
                    .unwrap();
                keys.insert(name.to_string(), pkcs8_scalar(&der));
            } else if let Some((k, v)) = line.split_once(" = ") {
                record.insert(k.to_string(), v.trim_matches('"').to_string());
            } else if line.is_empty() && !record.is_empty() {
                let r = std::mem::take(&mut record);
                let (Some(hash), Some(key)) = (r.get("DigestSign"), r.get("Key")) else {
                    continue;
                };
                if r.get("NonceType").map(String::as_str) != Some("deterministic") {
                    continue;
                }
                let Some(curve) = curve_of(key.split('_').next().unwrap()) else {
                    continue;
                };
                let name = hash.to_lowercase();
                let md = cryptography_crypto::hash::MessageDigest::from_name(&name).unwrap();
                let digest = cryptography_crypto::hash::hash(md, r["Input"].as_bytes()).unwrap();
                let d = left_pad(&keys[key], curve.len()).unwrap();
                match ecdsa_sign(curve, &d, &digest, &name, true) {
                    Ok(rs) => {
                        assert_eq!(der_signature(&rs).ok().unwrap(), hex(&r["Output"]));
                        matched += 1;
                    }
                    Err(_) => refused += 1,
                }
            }
        }
        // P-192/SHA-256, P-224/SHA-224, P-256/SHA-256 and SHA-384,
        // P-384/SHA-384 and P-521/SHA-512, each for two messages.
        assert_eq!(matched, 12);
        assert_eq!(refused, 38);
    }

    #[test]
    fn der_round_trip() {
        let rs = [[0u8, 0x80, 1].as_slice(), &[0, 0, 5]].concat();
        let der = der_signature(&rs).ok().unwrap();
        assert_eq!(der, [0x30, 8, 2, 3, 0, 0x80, 1, 2, 1, 5]);
        assert_eq!(parse_der_signature(&der, 3).unwrap(), rs);
        assert!(parse_der_signature(&der, 1).is_none());
        assert!(parse_der_signature(&der[..9], 3).is_none());
    }

    #[test]
    fn ecdsa_input_encodings() {
        // A digest longer than the order is truncated, a shorter one padded.
        assert_eq!(ecdsa_input(&[1, 2, 3], 16, 3).unwrap(), [1, 2, 0]);
        assert_eq!(ecdsa_input(&[1], 16, 3).unwrap(), [0, 1, 0]);
        assert_eq!(ecdsa_input(&[1, 2], 521, 64).unwrap().len(), 64);
        assert!(ecdsa_input(&[0; 65], 521, 64).is_none());
    }
}
