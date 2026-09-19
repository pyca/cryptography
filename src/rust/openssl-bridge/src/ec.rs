//! Named-curve EC keys with validated points, scalar ranges, and distinct key roles.
use crate::{
    error::{check, pointer},
    ffi,
    hash::Algorithm,
    secret::SecretBytes,
    Error, Result,
};
use std::{
    ffi::CStr,
    ptr::{self, NonNull},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
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
impl Curve {
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "secp192r1" | "prime192v1" => Ok(Self::P192),
            "secp224r1" => Ok(Self::P224),
            "secp256r1" | "prime256v1" => Ok(Self::P256),
            "secp384r1" => Ok(Self::P384),
            "secp521r1" => Ok(Self::P521),
            "secp256k1" => Ok(Self::Secp256k1),
            "brainpoolP256r1" => Ok(Self::BrainpoolP256r1),
            "brainpoolP384r1" => Ok(Self::BrainpoolP384r1),
            "brainpoolP512r1" => Ok(Self::BrainpoolP512r1),
            _ => Err(Error::Unsupported("unsupported named EC curve")),
        }
    }
    pub fn name(self) -> &'static str {
        self.native_name().to_str().unwrap()
    }
    fn native_name(self) -> &'static CStr {
        match self {
            Self::P192 => c"prime192v1",
            Self::P224 => c"secp224r1",
            Self::P256 => c"prime256v1",
            Self::P384 => c"secp384r1",
            Self::P521 => c"secp521r1",
            Self::Secp256k1 => c"secp256k1",
            Self::BrainpoolP256r1 => c"brainpoolP256r1",
            Self::BrainpoolP384r1 => c"brainpoolP384r1",
            Self::BrainpoolP512r1 => c"brainpoolP512r1",
        }
    }
    pub fn bits(self) -> usize {
        match self {
            Self::P192 => 192,
            Self::P224 => 224,
            Self::P256 | Self::Secp256k1 | Self::BrainpoolP256r1 => 256,
            Self::P384 | Self::BrainpoolP384r1 => 384,
            Self::P521 => 521,
            Self::BrainpoolP512r1 => 512,
        }
    }
    pub fn field_size(self) -> usize {
        self.bits().div_ceil(8)
    }
    pub fn is_available(self) -> bool {
        Ec::new(self).is_ok()
    }
}
#[derive(Clone, Copy)]
pub enum PointEncoding {
    Compressed,
    Uncompressed,
}
#[derive(Clone, Copy)]
pub enum Nonce {
    Random,
    Deterministic,
}

struct Number(NonNull<ffi::BIGNUM>);
impl Number {
    fn empty() -> Result<Self> {
        // SAFETY: Native allocator has no preconditions.
        pointer(unsafe { ffi::BN_new() }).map(Self)
    }
    fn from_bytes(bytes: &[u8], maximum: usize) -> Result<Self> {
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        let bytes = &bytes[first..];
        if bytes.len() > maximum {
            return Err(Error::InvalidInput("EC integer exceeds field size"));
        }
        #[allow(clippy::useless_conversion)]
        let len = bytes
            .len()
            .try_into()
            .map_err(|_| Error::InvalidInput("EC integer exceeds native limit"))?;
        // SAFETY: The bounded input covers its native integer length. NULL requests ownership.
        pointer(unsafe { ffi::BN_bin2bn(bytes.as_ptr(), len, ptr::null_mut()) }).map(Self)
    }
    fn ptr(&self) -> *mut ffi::BIGNUM {
        self.0.as_ptr()
    }
}
impl Drop for Number {
    fn drop(&mut self) {
        // SAFETY: This uniquely owns the BIGNUM and erases private scalar material.
        unsafe { ffi::BN_clear_free(self.ptr()) };
    }
}
struct NumberContext(NonNull<ffi::BN_CTX>);
impl NumberContext {
    fn new() -> Result<Self> {
        // SAFETY: Native allocator has no preconditions.
        pointer(unsafe { ffi::BN_CTX_new() }).map(Self)
    }
    fn ptr(&mut self) -> *mut ffi::BN_CTX {
        self.0.as_ptr()
    }
}
impl Drop for NumberContext {
    fn drop(&mut self) {
        // SAFETY: This uniquely owns the context and its native temporary numbers.
        unsafe { ffi::BN_CTX_free(self.0.as_ptr()) };
    }
}
struct Point(NonNull<ffi::EC_POINT>);
impl Drop for Point {
    fn drop(&mut self) {
        // SAFETY: This uniquely owns the point.
        unsafe { ffi::EC_POINT_clear_free(self.0.as_ptr()) };
    }
}
struct Ec(NonNull<ffi::EC_KEY>);
impl Ec {
    fn new(curve: Curve) -> Result<Self> {
        crate::initialize()?;
        // SAFETY: Static NUL-terminated curve name; the object table is immutable.
        let nid = unsafe { ffi::OBJ_sn2nid(curve.native_name().as_ptr()) };
        if nid == 0 {
            return Err(Error::Unsupported("EC curve is unavailable"));
        }
        // SAFETY: Native named-curve constructor returns an owned key with a group.
        let key = Self(pointer(unsafe { ffi::EC_KEY_new_by_curve_name(nid) })?);
        let cofactor = Number::empty()?;
        let mut ctx = NumberContext::new()?;
        // SAFETY: New key owns a complete named group; outputs are exclusive allocations.
        check(unsafe { ffi::EC_GROUP_get_cofactor(key.group(), cofactor.ptr(), ctx.ptr()) })?;
        // SAFETY: The query reads an initialized number without mutation.
        if unsafe { ffi::BN_is_one(cofactor.ptr()) } != 1 {
            return Err(Error::Unsupported("EC curves must have cofactor one"));
        }
        Ok(key)
    }
    fn ptr(&self) -> *mut ffi::EC_KEY {
        self.0.as_ptr()
    }
    fn group(&self) -> *const ffi::EC_GROUP {
        // SAFETY: Every Ec is constructed with a valid named curve; borrow lasts with self.
        unsafe { ffi::EC_KEY_get0_group(self.ptr()) }
    }
    fn point(&self) -> Result<Point> {
        // SAFETY: The group is a complete native named group owned by self.
        pointer(unsafe { ffi::EC_POINT_new(self.group()) }).map(Point)
    }
    fn validate_point(&self, point: &Point, ctx: &mut NumberContext) -> Result<()> {
        // SAFETY: Point and context are owned; point was created for this exact group.
        let infinity = unsafe { ffi::EC_POINT_is_at_infinity(self.group(), point.0.as_ptr()) };
        // SAFETY: Same group/point invariant; temporary number context is exclusive.
        let on_curve =
            unsafe { ffi::EC_POINT_is_on_curve(self.group(), point.0.as_ptr(), ctx.ptr()) };
        if infinity != 0 || on_curve != 1 {
            let _ = Error::capture();
            return Err(Error::InvalidInput("EC point is infinity or off the curve"));
        }
        Ok(())
    }
}
impl Drop for Ec {
    fn drop(&mut self) {
        // SAFETY: This releases the owned EC key reference and its components.
        unsafe { ffi::EC_KEY_free(self.ptr()) };
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn infinity_is_not_a_public_key() {
        let ec = Ec::new(Curve::P256).unwrap();
        let point = ec.point().unwrap();
        // EC_POINT_new initializes a valid point-at-infinity object, which
        // must be rejected even though it belongs to the correct group.
        assert!(ec
            .validate_point(&point, &mut NumberContext::new().unwrap())
            .is_err());
    }
}
struct Key {
    pkey: NonNull<ffi::EVP_PKEY>,
    curve: Curve,
}
// SAFETY: Keys are complete and immutable; operations own independent native contexts.
unsafe impl Send for Key {}
// SAFETY: The built-in EC key implementation supports shared immutable key use.
unsafe impl Sync for Key {}
impl Key {
    fn from_ec(ec: Ec, curve: Curve) -> Result<Self> {
        // SAFETY: The native check examines a complete key assembled by our constructors.
        check(unsafe { ffi::EC_KEY_check_key(ec.ptr()) })?;
        let key = Self {
            // SAFETY: Native allocator has no preconditions.
            pkey: pointer(unsafe { ffi::EVP_PKEY_new() })?,
            curve,
        };
        // SAFETY: set1 retains a reference; ec drops its reference on both paths.
        check(unsafe { ffi::EVP_PKEY_set1_EC_KEY(key.pkey.as_ptr(), ec.ptr()) })?;
        Ok(key)
    }
    fn ec(&self) -> *const ffi::EC_KEY {
        // SAFETY: Every pkey was constructed from a legacy EC key using set1.
        // Native operations never replace the original key or its algorithm.
        unsafe { ffi::EVP_PKEY_get0_EC_KEY(self.pkey.as_ptr()) }
    }
    fn public_bytes(&self, encoding: PointEncoding) -> Result<Vec<u8>> {
        let mut ctx = NumberContext::new()?;
        let length = match encoding {
            PointEncoding::Compressed => 1 + self.curve.field_size(),
            PointEncoding::Uncompressed => 1 + 2 * self.curve.field_size(),
        };
        let mut result = vec![0; length];
        let form = match encoding {
            PointEncoding::Compressed => ffi::point_conversion_form_t_POINT_CONVERSION_COMPRESSED,
            PointEncoding::Uncompressed => {
                ffi::point_conversion_form_t_POINT_CONVERSION_UNCOMPRESSED
            }
        };
        // SAFETY: Key is validated and owns its group/point. Capacity is supplied
        // explicitly and matches this curve's fixed-size point representation.
        let written = unsafe {
            ffi::EC_POINT_point2oct(
                ffi::EC_KEY_get0_group(self.ec()),
                ffi::EC_KEY_get0_public_key(self.ec()),
                form,
                result.as_mut_ptr(),
                result.len(),
                ctx.ptr(),
            )
        };
        if written != result.len() {
            return Err(Error::capture());
        }
        Ok(result)
    }
    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let encoded = self.public_bytes(PointEncoding::Uncompressed)?;
        let (x, y) = encoded[1..].split_at(self.curve.field_size());
        Ok((x.to_vec(), y.to_vec()))
    }
}
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: This is the unique owner of the EVP key reference.
        unsafe { ffi::EVP_PKEY_free(self.pkey.as_ptr()) };
    }
}
struct Operation(NonNull<ffi::EVP_PKEY_CTX>);
impl Operation {
    fn new(key: &Key) -> Result<Self> {
        // SAFETY: A complete immutable key is live; native context retains its reference.
        pointer(unsafe { ffi::EVP_PKEY_CTX_new(key.pkey.as_ptr(), ptr::null_mut()) }).map(Self)
    }
    fn ptr(&mut self) -> *mut ffi::EVP_PKEY_CTX {
        self.0.as_ptr()
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        // SAFETY: This uniquely owns the operation context.
        unsafe { ffi::EVP_PKEY_CTX_free(self.0.as_ptr()) };
    }
}

pub struct PrivateKey(Key);
pub struct PublicKey(Key);
impl PrivateKey {
    pub fn generate(curve: Curve) -> Result<Self> {
        let ec = Ec::new(curve)?;
        // SAFETY: The owned key has a supported named group and no published references.
        check(unsafe { ffi::EC_KEY_generate_key(ec.ptr()) })?;
        Key::from_ec(ec, curve).map(Self)
    }
    pub fn from_scalar(curve: Curve, scalar: &[u8]) -> Result<Self> {
        let ec = Ec::new(curve)?;
        let scalar = Number::from_bytes(scalar, curve.field_size())?;
        let order = Number::empty()?;
        let mut ctx = NumberContext::new()?;
        // SAFETY: Named group is complete; order and context are unique temporary values.
        check(unsafe { ffi::EC_GROUP_get_order(ec.group(), order.ptr(), ctx.ptr()) })?;
        // SAFETY: Both numbers are initialized, unsigned, and borrowed for comparison.
        if unsafe {
            ffi::BN_num_bits(scalar.ptr()) == 0 || ffi::BN_cmp(scalar.ptr(), order.ptr()) >= 0
        } {
            return Err(Error::InvalidInput("EC scalar must be in [1, order)"));
        }
        let point = ec.point()?;
        // SAFETY: Scalar lies in the group order; NULL selects generator-only
        // multiplication, avoiding invalid optional point/scalar combinations.
        check(unsafe {
            ffi::EC_POINT_mul(
                ec.group(),
                point.0.as_ptr(),
                scalar.ptr(),
                ptr::null(),
                ptr::null(),
                ctx.ptr(),
            )
        })?;
        ec.validate_point(&point, &mut ctx)?;
        // SAFETY: Setters copy components into an exclusive key. Scalar is valid
        // and the point was computed from that scalar and this exact group.
        check(unsafe { ffi::EC_KEY_set_private_key(ec.ptr(), scalar.ptr()) })?;
        // SAFETY: The live point belongs to the key's group; setter copies it.
        check(unsafe { ffi::EC_KEY_set_public_key(ec.ptr(), point.0.as_ptr()) })?;
        Key::from_ec(ec, curve).map(Self)
    }
    pub fn curve(&self) -> Curve {
        self.0.curve
    }
    pub fn scalar(&self) -> Result<SecretBytes> {
        // SAFETY: Only private constructors produce this type, so scalar is non-NULL.
        let scalar = unsafe { ffi::EC_KEY_get0_private_key(self.0.ec()) };
        // SAFETY: Scalar is immutable and validated against the group order.
        let bits = unsafe { ffi::BN_num_bits(scalar) };
        let length = usize::try_from(bits)
            .map_err(|_| Error::InvalidState("negative scalar size"))?
            .div_ceil(8);
        let mut result: SecretBytes = vec![0; length].into();
        // SAFETY: The destination has the exact size of this positive scalar.
        let written = unsafe { ffi::BN_bn2bin(scalar, result.as_mut().as_mut_ptr()) };
        crate::error::check_len(written as usize, length)?;
        Ok(result)
    }
    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_encoded(
            self.curve(),
            &self.0.public_bytes(PointEncoding::Uncompressed)?,
        )
    }
    pub fn sign_digest(&self, digest: Algorithm, prehash: &[u8], nonce: Nonce) -> Result<Vec<u8>> {
        if digest.is_xof() || prehash.len() != digest.output_size()? {
            return Err(Error::InvalidInput("incorrect ECDSA digest length"));
        }
        let mut operation = Operation::new(&self.0)?;
        // SAFETY: This operation owns a complete EC private key reference.
        check(unsafe { ffi::EVP_PKEY_sign_init(operation.ptr()) })?;
        if matches!(nonce, Nonce::Deterministic) {
            #[cfg(all(backend = "openssl", openssl_320))]
            {
                // SAFETY: Deterministic signing needs the selected digest and
                // nonce mode; both controls are confined to a signing operation.
                check(unsafe { ffi::OB_signature_md(operation.ptr(), digest.as_ptr()) })?;
                // SAFETY: Shim constructs a typed OSSL_PARAM for deterministic nonces.
                check(unsafe { ffi::OB_signature_nonce(operation.ptr(), 1) })?;
            }
            #[cfg(not(all(backend = "openssl", openssl_320)))]
            return Err(Error::Unsupported("deterministic ECDSA is unavailable"));
        }
        let mut length = 0;
        // SAFETY: NULL output queries the maximum DER signature length without writing.
        check(unsafe {
            ffi::EVP_PKEY_sign(
                operation.ptr(),
                ptr::null_mut(),
                &mut length,
                prehash.as_ptr(),
                prehash.len(),
            )
        })?;
        crate::error::check_len_at_most(length, 2 * self.curve().field_size() + 16)?;
        let mut output = vec![0; length];
        // SAFETY: Output fits the queried maximum; native API receives its capacity.
        check(unsafe {
            ffi::EVP_PKEY_sign(
                operation.ptr(),
                output.as_mut_ptr(),
                &mut length,
                prehash.as_ptr(),
                prehash.len(),
            )
        })?;
        crate::error::check_len_at_most(length, output.len())?;
        output.truncate(length);
        Ok(output)
    }
    pub fn exchange(&self, peer: &PublicKey) -> Result<SecretBytes> {
        if self.curve() != peer.curve() {
            return Err(Error::InvalidInput("ECDH curves must match"));
        }
        let mut operation = Operation::new(&self.0)?;
        // SAFETY: Initialized operation owns the validated private key.
        check(unsafe { ffi::EVP_PKEY_derive_init(operation.ptr()) })?;
        // SAFETY: Peer has a valid non-infinity point in the same cofactor-one group.
        check(unsafe { ffi::EVP_PKEY_derive_set_peer(operation.ptr(), peer.0.pkey.as_ptr()) })?;
        let mut length = self.curve().field_size();
        let mut output: SecretBytes = vec![0; length].into();
        // SAFETY: Output is the full field width and its capacity is supplied;
        // native ECDH for these groups returns a padded x-coordinate of that size.
        check(unsafe {
            ffi::EVP_PKEY_derive(operation.ptr(), output.as_mut().as_mut_ptr(), &mut length)
        })?;
        crate::error::check_len(length, output.as_ref().len())?;
        Ok(output)
    }
}
impl PublicKey {
    pub fn from_encoded(curve: Curve, encoded: &[u8]) -> Result<Self> {
        let valid = match encoded.first() {
            Some(2 | 3) => encoded.len() == 1 + curve.field_size(),
            Some(4) => encoded.len() == 1 + 2 * curve.field_size(),
            _ => false,
        };
        if !valid {
            return Err(Error::InvalidInput("invalid EC point encoding"));
        }
        let ec = Ec::new(curve)?;
        let point = ec.point()?;
        let mut ctx = NumberContext::new()?;
        // SAFETY: Native parser is supplied the checked buffer and its actual length;
        // point and temporary number context are exclusively owned for this group.
        check(unsafe {
            ffi::EC_POINT_oct2point(
                ec.group(),
                point.0.as_ptr(),
                encoded.as_ptr(),
                encoded.len(),
                ctx.ptr(),
            )
        })?;
        ec.validate_point(&point, &mut ctx)?;
        // SAFETY: Setter copies a validated point into a key with the same group.
        check(unsafe { ffi::EC_KEY_set_public_key(ec.ptr(), point.0.as_ptr()) })?;
        Key::from_ec(ec, curve).map(Self)
    }
    pub fn from_coordinates(curve: Curve, x: &[u8], y: &[u8]) -> Result<Self> {
        let width = curve.field_size();
        let mut encoded = vec![0; 1 + 2 * width];
        encoded[0] = 4;
        let strip = |b: &[u8]| b.iter().position(|&v| v != 0).unwrap_or(b.len());
        let x = &x[strip(x)..];
        let y = &y[strip(y)..];
        if x.len() > width || y.len() > width {
            return Err(Error::InvalidInput("EC coordinate exceeds field size"));
        }
        encoded[1 + width - x.len()..1 + width].copy_from_slice(x);
        encoded[1 + 2 * width - y.len()..].copy_from_slice(y);
        Self::from_encoded(curve, &encoded)
    }
    pub fn curve(&self) -> Curve {
        self.0.curve
    }
    pub fn to_encoded(&self, encoding: PointEncoding) -> Result<Vec<u8>> {
        self.0.public_bytes(encoding)
    }
    pub fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        self.0.coordinates()
    }
    pub fn verify_digest(
        &self,
        digest: Algorithm,
        prehash: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        if digest.is_xof() || prehash.len() != digest.output_size()? {
            return Err(Error::InvalidInput("incorrect ECDSA digest length"));
        }
        let mut operation = Operation::new(&self.0)?;
        // SAFETY: Operation retains the validated public key.
        check(unsafe { ffi::EVP_PKEY_verify_init(operation.ptr()) })?;
        // SAFETY: Signature and prehash borrows cover their exact lengths; native
        // verification receives no output pointer and cannot mutate either input.
        let valid = unsafe {
            ffi::EVP_PKEY_verify(
                operation.ptr(),
                signature.as_ptr(),
                signature.len(),
                prehash.as_ptr(),
                prehash.len(),
            )
        };
        if valid == 1 {
            Ok(true)
        } else {
            let _ = Error::capture();
            Ok(false)
        }
    }
}
