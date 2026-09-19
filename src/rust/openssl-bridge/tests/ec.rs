use openssl_bridge::{
    ec::{Curve, Nonce, PointEncoding, PrivateKey, PublicKey},
    hash::{self, Algorithm},
};

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn p256_generator_and_scalar_boundaries() {
    let key = PrivateKey::from_scalar(Curve::P256, &[1]).unwrap();
    assert_eq!(key.scalar().unwrap().as_ref(), &[1]);
    let generator = hex(concat!(
        "04",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    ));
    let public = key.public_key().unwrap();
    assert_eq!(
        public.to_encoded(PointEncoding::Uncompressed).unwrap(),
        generator
    );
    let (x, y) = public.coordinates().unwrap();
    assert_eq!(
        PublicKey::from_coordinates(Curve::P256, &x, &y)
            .unwrap()
            .to_encoded(PointEncoding::Uncompressed)
            .unwrap(),
        generator
    );
    let order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    for scalar in [&[][..], &[0], &[0; 32], &order, &[255; 33]] {
        assert!(PrivateKey::from_scalar(Curve::P256, scalar).is_err());
    }
    let mut last = order;
    last[31] -= 1;
    let negated = PrivateKey::from_scalar(Curve::P256, &last)
        .unwrap()
        .public_key()
        .unwrap();
    assert_eq!(negated.coordinates().unwrap().0, x);
    assert_ne!(negated.coordinates().unwrap().1, y);
}

#[test]
fn invalid_points_and_encodings_are_rejected() {
    let valid = PrivateKey::from_scalar(Curve::P256, &[1])
        .unwrap()
        .public_key()
        .unwrap()
        .to_encoded(PointEncoding::Uncompressed)
        .unwrap();
    for input in [&[][..], &[0], &valid[..64], &[4; 66]] {
        assert!(PublicKey::from_encoded(Curve::P256, input).is_err());
    }
    let mut hybrid = valid.clone();
    hybrid[0] = 7;
    assert!(PublicKey::from_encoded(Curve::P256, &hybrid).is_err());
    let mut off_curve = valid;
    off_curve[64] ^= 1;
    assert!(PublicKey::from_encoded(Curve::P256, &off_curve).is_err());
    assert!(PublicKey::from_coordinates(Curve::P256, &[0], &[0]).is_err());
    // x equal to the field modulus must not be silently reduced.
    let field = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    assert!(PublicKey::from_coordinates(Curve::P256, &field, &[1]).is_err());
    assert!(PublicKey::from_coordinates(Curve::P256, &[1; 33], &[1]).is_err());
}

#[test]
#[cfg(not(all(backend = "openssl", openssl_320)))]
fn unsupported_deterministic_signatures_are_rejected() {
    let key = PrivateKey::from_scalar(Curve::P256, &[42]).unwrap();
    let md = Algorithm::from_name("sha256").unwrap();
    assert!(key.sign_digest(md, &[0; 32], Nonce::Deterministic).is_err());
}

#[test]
fn all_supported_curves_sign_and_exchange() {
    let sha256 = Algorithm::from_name("sha256").unwrap();
    let digest = hash::digest(sha256, b"EC operation tests").unwrap();
    for curve in [
        Curve::P192,
        Curve::P224,
        Curve::P256,
        Curve::P384,
        Curve::P521,
        Curve::Secp256k1,
        Curve::BrainpoolP256r1,
        Curve::BrainpoolP384r1,
        Curve::BrainpoolP512r1,
    ] {
        if !curve.is_available() {
            continue;
        }
        let alice = PrivateKey::generate(curve).unwrap();
        let bob = PrivateKey::from_scalar(curve, &[42]).unwrap();
        let public = alice.public_key().unwrap();
        let compressed = public.to_encoded(PointEncoding::Compressed).unwrap();
        assert_eq!(
            PublicKey::from_encoded(curve, &compressed)
                .unwrap()
                .coordinates()
                .unwrap(),
            public.coordinates().unwrap()
        );
        assert!(public.verify_digest(sha256, &[], &[]).is_err());
        let signature = alice.sign_digest(sha256, &digest, Nonce::Random).unwrap();
        assert!(public.verify_digest(sha256, &digest, &signature).unwrap());
        assert!(!bob
            .public_key()
            .unwrap()
            .verify_digest(sha256, &digest, &signature)
            .unwrap());
        assert!(!public
            .verify_digest(sha256, &digest, &[0x30, 0x80])
            .unwrap());
        let mut trailing = signature.clone();
        trailing.push(0);
        assert!(!public.verify_digest(sha256, &digest, &trailing).unwrap());
        assert!(alice
            .sign_digest(sha256, &digest[..31], Nonce::Random)
            .is_err());
        let a = alice.exchange(&bob.public_key().unwrap()).unwrap();
        let b = bob.exchange(&public).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
        assert_eq!(a.as_ref().len(), curve.field_size());
    }
    let a = PrivateKey::generate(Curve::P256).unwrap();
    let b = PrivateKey::generate(Curve::P384).unwrap();
    assert!(a.exchange(&b.public_key().unwrap()).is_err());
}

#[test]
#[cfg(all(backend = "openssl", openssl_320))]
fn deterministic_nonce_is_repeatable_and_message_bound() {
    let key = PrivateKey::from_scalar(Curve::P256, &[42]).unwrap();
    let md = Algorithm::from_name("sha256").unwrap();
    let digest = hash::digest(md, b"message").unwrap();
    let a = key.sign_digest(md, &digest, Nonce::Deterministic).unwrap();
    let b = key.sign_digest(md, &digest, Nonce::Deterministic).unwrap();
    assert_eq!(a, b);
    assert!(key
        .public_key()
        .unwrap()
        .verify_digest(md, &digest, &a)
        .unwrap());
    let other = hash::digest(md, b"other").unwrap();
    assert_ne!(
        a,
        key.sign_digest(md, &other, Nonce::Deterministic).unwrap()
    );
}
