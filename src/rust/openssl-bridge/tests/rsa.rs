use openssl_bridge::{
    hash::{self, Algorithm},
    rsa::*,
};

#[test]
fn rsa_signatures_padding_and_components() {
    let key = PrivateKey::generate(1024, 65537).unwrap();
    assert_eq!(key.bits(), 1024);
    let public = key.public_key().unwrap();
    let exported = key.export_components().unwrap();
    let restored = PrivateKey::from_components(exported.components()).unwrap();
    let sha256 = Algorithm::from_name("sha256").unwrap();
    let digest = hash::digest(sha256, b"message").unwrap();
    let pkcs1 = key
        .sign_digest(sha256, &digest, SigningPadding::Pkcs1v15)
        .unwrap();
    assert_eq!(
        public.recover_pkcs1v15(&pkcs1, Some(sha256)).unwrap(),
        digest
    );
    let raw = key.sign_pkcs1v15_block(b"raw block").unwrap();
    assert!(public.verify_pkcs1v15_block(b"raw block", &raw).unwrap());
    assert!(!public.verify_pkcs1v15_block(b"other block", &raw).unwrap());
    assert_eq!(public.recover_pkcs1v15(&raw, None).unwrap(), b"raw block");
    for (sign, verify) in [
        (SigningPadding::Pkcs1v15, VerificationPadding::Pkcs1v15),
        (
            SigningPadding::Pss {
                mgf1: sha256,
                salt: SaltLength::Digest,
            },
            VerificationPadding::Pss {
                mgf1: sha256,
                salt: SaltLength::Digest,
            },
        ),
        (
            SigningPadding::Pss {
                mgf1: sha256,
                salt: SaltLength::Maximum,
            },
            VerificationPadding::Pss {
                mgf1: sha256,
                salt: SaltLength::Maximum,
            },
        ),
        (
            SigningPadding::Pss {
                mgf1: sha256,
                salt: SaltLength::Exact(0),
            },
            VerificationPadding::PssAuto { mgf1: sha256 },
        ),
    ] {
        let signature = restored.sign_digest(sha256, &digest, sign).unwrap();
        assert_eq!(signature.len(), 128);
        assert!(public
            .verify_digest(sha256, &digest, &signature, verify)
            .unwrap());
        let wrong = hash::digest(sha256, b"wrong").unwrap();
        assert!(!public
            .verify_digest(sha256, &wrong, &signature, verify)
            .unwrap());
        assert!(!public
            .verify_digest(sha256, &digest, &signature[..127], verify)
            .unwrap());
    }
    assert!(key
        .sign_digest(sha256, &[0; 31], SigningPadding::Pkcs1v15)
        .is_err());
    let mut invalid = exported.components();
    invalid.iqmp = &[1];
    assert!(PrivateKey::from_components(invalid).is_err());
    let mut unchecked = exported.components();
    unchecked.iqmp = &[1];
    assert!(PrivateKey::from_components_with_validation(unchecked, Validation::Structural).is_ok());
    let mut malformed = exported.components();
    malformed.n = &[17];
    assert!(
        PrivateKey::from_components_with_validation(malformed, Validation::Structural).is_err()
    );
    let even_public = PublicKey::from_components(&[10], &[3]).unwrap();
    assert_eq!(even_public.export_components().unwrap().n, [10]);
    assert!(PublicKey::from_components(&[0], &[3]).is_err());
    assert!(PublicKey::from_components(&[17], &[2]).is_err());
}

#[test]
fn rsa_oaep_label_and_digest_are_binding() {
    let key = PrivateKey::generate(1024, 65537).unwrap();
    let public = key.public_key().unwrap();
    let sha256 = Algorithm::from_name("sha256").unwrap();
    let padding = EncryptionPadding::Oaep {
        digest: sha256,
        mgf1: sha256,
        label: b"context",
    };
    let encrypted = public.encrypt(b"secret", padding).unwrap();
    assert_eq!(
        key.decrypt(&encrypted, padding).unwrap().as_ref(),
        b"secret"
    );
    let wrong = EncryptionPadding::Oaep {
        digest: sha256,
        mgf1: sha256,
        label: b"different",
    };
    assert!(key.decrypt(&encrypted, wrong).is_err());
    let mut guarded = [0x55; 130];
    let n = key
        .decrypt_into(&encrypted, padding, &mut guarded[1..129])
        .unwrap();
    assert_eq!(&guarded[1..1 + n], b"secret");
    assert!(guarded[1 + n..129].iter().all(|b| *b == 0));
    assert_eq!((guarded[0], guarded[129]), (0x55, 0x55));
    guarded.fill(0x55);
    assert!(key
        .decrypt_into(&encrypted, wrong, &mut guarded[1..129])
        .is_err());
    assert!(guarded[1..129].iter().all(|b| *b == 0));
    assert_eq!((guarded[0], guarded[129]), (0x55, 0x55));
    assert!(key.decrypt(&encrypted[..127], padding).is_err());
    assert!(public.encrypt(&[0; 63], padding).is_err());
    let encrypted = public
        .encrypt(b"secret", EncryptionPadding::Pkcs1v15)
        .unwrap();
    assert_eq!(
        key.decrypt(&encrypted, EncryptionPadding::Pkcs1v15)
            .unwrap()
            .as_ref(),
        b"secret"
    );
    let empty_label = EncryptionPadding::Oaep {
        digest: sha256,
        mgf1: sha256,
        label: b"",
    };
    let encrypted = public.encrypt(b"", empty_label).unwrap();
    assert!(key
        .decrypt(&encrypted, empty_label)
        .unwrap()
        .as_ref()
        .is_empty());
}
