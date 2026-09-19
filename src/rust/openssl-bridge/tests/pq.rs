#![cfg(any(openssl_350, backend = "boringssl", backend = "awslc"))]
#[cfg(not(backend = "boringssl"))]
use openssl_bridge::hash::{Algorithm, Hasher};
use openssl_bridge::{mldsa, mlkem};
#[test]
fn mldsa_message_context_and_external_mu() {
    for variant in [
        mldsa::Variant::MlDsa44,
        mldsa::Variant::MlDsa65,
        mldsa::Variant::MlDsa87,
    ] {
        let key = mldsa::PrivateKey::from_seed(variant, &[7; 32]).unwrap();
        assert_eq!(key.public_key().as_bytes().len(), variant.public_key_size());
        let public = key.public_key();
        let imported = mldsa::PublicKey::from_bytes(variant, public.as_bytes()).unwrap();
        let signature = key.sign(b"message", b"context").unwrap();
        assert_eq!(signature.len(), variant.signature_size());
        assert!(imported.verify(b"message", b"context", &signature).unwrap());
        assert!(!imported.verify(b"message", b"wrong", &signature).unwrap());
        assert!(!imported.verify(b"wrong", b"context", &signature).unwrap());
        assert!(!imported
            .verify(b"message", b"context", &signature[..signature.len() - 1])
            .unwrap());
        assert!(key.sign(b"", &[0; 256]).is_err());
        assert!(public.verify(b"", &[0; 256], &signature).is_err());
        assert!(mldsa::PublicKey::from_bytes(variant, &public.as_bytes()[1..]).is_err());
        let arbitrary_mu = [8; 64];
        let mu_signature = key.sign_mu(&arbitrary_mu).unwrap();
        assert!(public.verify_mu(&arbitrary_mu, &mu_signature).unwrap());
        assert!(!public.verify_mu(&[9; 64], &mu_signature).unwrap());
        #[cfg(not(backend = "boringssl"))]
        {
            // FIPS 204: mu = SHAKE256(SHAKE256(pk, 64) || 0 || ctx_len || ctx || M, 64).
            let shake = Algorithm::from_name("SHAKE256").unwrap();
            let mut tr = [0; 64];
            let mut h = Hasher::new(shake).unwrap();
            h.update(public.as_bytes()).unwrap();
            h.finish_xof(&mut tr).unwrap();
            let mut h = Hasher::new(shake).unwrap();
            h.update(&tr).unwrap();
            h.update(&[0, 7]).unwrap();
            h.update(b"context").unwrap();
            h.update(b"message").unwrap();
            let mut mu = [0; 64];
            h.finish_xof(&mut mu).unwrap();
            assert!(public.verify_mu(&mu, &signature).unwrap());
            let mu_signature = key.sign_mu(&mu).unwrap();
            assert!(public
                .verify(b"message", b"context", &mu_signature)
                .unwrap());
            mu[0] ^= 1;
            assert!(!public.verify_mu(&mu, &signature).unwrap());
        }
        let generated = mldsa::PrivateKey::generate(variant).unwrap();
        assert_ne!(generated.public_key().as_bytes(), public.as_bytes());
    }
}
#[test]
fn mlkem_encapsulation_and_implicit_rejection() {
    for variant in [mlkem::Variant::MlKem768, mlkem::Variant::MlKem1024] {
        let key = mlkem::PrivateKey::from_seed(variant, &[5; 64]).unwrap();
        let public = key.public_key();
        let imported = mlkem::PublicKey::from_bytes(variant, public.as_bytes()).unwrap();
        let (mut ciphertext, secret) = imported.encapsulate().unwrap();
        assert_eq!(ciphertext.len(), variant.ciphertext_size());
        assert_eq!(
            secret.as_ref(),
            key.decapsulate(&ciphertext).unwrap().as_ref()
        );
        assert!(key.decapsulate(&ciphertext[1..]).is_err());
        ciphertext[0] ^= 1;
        let rejected = key.decapsulate(&ciphertext).unwrap();
        assert_ne!(rejected.as_ref(), secret.as_ref());
        assert_eq!(
            key.decapsulate(&ciphertext).unwrap().as_ref(),
            rejected.as_ref()
        );
        assert!(mlkem::PublicKey::from_bytes(variant, &public.as_bytes()[1..]).is_err());
        let generated = mlkem::PrivateKey::generate(variant).unwrap();
        assert_ne!(generated.public_key().as_bytes(), public.as_bytes());
    }
}

fn field(vector: &str, name: &str) -> Vec<u8> {
    let hex = vector
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key == name).then_some(value)
        })
        .unwrap();
    hex.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn mldsa_known_answers() {
    for (variant, vector) in [
        (mldsa::Variant::MlDsa44, include_str!("vectors/mldsa44.txt")),
        (mldsa::Variant::MlDsa65, include_str!("vectors/mldsa65.txt")),
        (mldsa::Variant::MlDsa87, include_str!("vectors/mldsa87.txt")),
    ] {
        let seed: [u8; 32] = field(vector, "seed").try_into().unwrap();
        let key = mldsa::PrivateKey::from_seed(variant, &seed).unwrap();
        let public = key.public_key();
        assert_eq!(public.as_bytes(), field(vector, "public"));
        let message = field(vector, "message");
        let context = field(vector, "context");
        let signature = field(vector, "signature");
        let mu: [u8; 64] = field(vector, "mu").try_into().unwrap();
        assert!(public.verify(&message, &context, &signature).unwrap());
        assert!(public.verify_mu(&mu, &signature).unwrap());
        let generated = key.sign_mu(&mu).unwrap();
        assert!(public.verify(&message, &context, &generated).unwrap());
    }
}
#[test]
fn mlkem_known_answers() {
    for (variant, vector) in [
        (
            mlkem::Variant::MlKem768,
            include_str!("vectors/mlkem768.txt"),
        ),
        (
            mlkem::Variant::MlKem1024,
            include_str!("vectors/mlkem1024.txt"),
        ),
    ] {
        let seed: [u8; 64] = field(vector, "seed").try_into().unwrap();
        assert_eq!(field(vector, "public").len(), variant.public_key_size());
        let key = mlkem::PrivateKey::from_seed(variant, &seed).unwrap();
        assert_eq!(key.public_key().as_bytes(), field(vector, "public"));
        assert_eq!(
            key.decapsulate(&field(vector, "ciphertext"))
                .unwrap()
                .as_ref(),
            field(vector, "secret")
        );
        assert_eq!(
            key.decapsulate(&field(vector, "rejected_ciphertext"))
                .unwrap()
                .as_ref(),
            field(vector, "rejected_secret")
        );
    }
}
