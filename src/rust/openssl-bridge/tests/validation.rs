use openssl_bridge::{
    aead,
    cipher::{Cipher, CipherKey, Direction, Stream, XtsDataUnit},
    containers::Pkcs12Error,
    gcm::{GcmCipher, GcmEncrypt},
    hash::{Algorithm, Hasher},
    kdf,
    mac::{Cmac, CmacCipher},
    rand, runtime, Error,
};

#[test]
fn rejected_aead_inputs_leave_output_untouched() {
    assert!(aead::Algorithm::from_name("CHACHA20-POLY1305").is_ok());
    assert!(aead::Algorithm::from_name("unknown").is_err());
    assert!(aead::Key::new(aead::Algorithm::Aes128Gcm, &[0; 15]).is_err());
    assert!(aead::Key::ccm(&[0; 15], 16).is_err());
    let key = aead::Key::new(aead::Algorithm::Aes128Gcm, &[0; 16]).unwrap();
    let mut output = [0xa5; 16];
    let mut tag = [0x5a; 16];
    assert!(key
        .seal_into(&[], &[], &[0; 16], &mut output, &mut tag)
        .is_err());
    assert!(key
        .seal_into(&[0; 12], &[b"a", b"b"], &[0; 16], &mut output, &mut tag)
        .is_err());
    assert!(key
        .seal_into(&[0; 12], &[], &[0; 16], &mut output[..15], &mut tag)
        .is_err());
    assert!(key
        .seal_into(&[0; 12], &[], &[0; 16], &mut output, &mut tag[..15])
        .is_err());
    assert_eq!(output, [0xa5; 16]);
    assert_eq!(tag, [0x5a; 16]);
}

#[test]
fn gcm_key_sizes_and_invalid_initialization() {
    assert!(GcmCipher::from_name("AES-128-CBC").is_err());
    assert!(GcmEncrypt::new(GcmCipher::Aes128, &[0; 15], &[0; 12]).is_err());
    assert!(GcmEncrypt::new(GcmCipher::Aes128, &[0; 16], &[]).is_err());
}

#[test]
fn streaming_cipher_metadata_and_xts_bounds() {
    assert_eq!(Cipher::Aes128Cbc.block_size().unwrap(), 16);
    let ctx = Stream::new(
        Cipher::Aes128Cbc,
        Direction::Encrypt,
        &[0; 16],
        &[0; 16],
        false,
    )
    .unwrap();
    assert_eq!(ctx.iv_size(), 16);
    assert!(ctx.update_capacity(usize::MAX).is_err());
    assert!(XtsDataUnit::new(Direction::Encrypt, &[0; 31], &[0; 16]).is_err());
    let key = CipherKey::new(Cipher::Aes128Cbc, &[0; 16], false).unwrap();
    assert!(key.start(Direction::Encrypt, &[0; 15]).is_err());
    let key = CipherKey::new(Cipher::Aes128Ecb, &[0; 16], false).unwrap();
    assert!(key
        .start(Direction::Encrypt, &[])
        .unwrap()
        .finish()
        .unwrap()
        .is_empty());
    if XtsDataUnit::is_available(32) {
        let key: Vec<u8> = (0..32).collect();
        let xts = XtsDataUnit::new(Direction::Encrypt, &key, &[0; 16]).unwrap();
        let mut guarded = [0xa5; 15];
        assert!(xts.crypt_into(&[0; 16], &mut guarded).is_err());
        assert_eq!(guarded, [0xa5; 15]);
    }
}

#[test]
fn digest_and_kdf_reject_incompatible_algorithms() {
    #[cfg(any(backend = "openssl", backend = "awslc"))]
    let sha256 = Algorithm::from_name("SHA256").unwrap();
    #[cfg(any(backend = "openssl", backend = "awslc"))]
    assert!(Hasher::new(sha256)
        .unwrap()
        .finish_xof(&mut [0; 16])
        .is_err());
    #[cfg(any(openssl_330, backend = "awslc"))]
    assert!(Hasher::new(sha256)
        .unwrap()
        .squeeze_xof(&mut [0; 16])
        .is_err());
    if let Ok(shake) = Algorithm::from_name("SHAKE128") {
        assert!(Hasher::new(shake).unwrap().finish().is_err());
        assert!(kdf::pbkdf2_hmac(
            shake,
            b"password",
            b"salt",
            1.try_into().unwrap(),
            &mut [0; 16]
        )
        .is_err());
        #[cfg(any(openssl_330, backend = "awslc"))]
        {
            let mut hash = Hasher::new(shake).unwrap();
            hash.squeeze_xof(&mut [0; 16]).unwrap();
            assert!(hash.update(b"late").is_err());
            assert!(hash.finish_xof(&mut [0; 16]).is_err());
        }
    }
    assert!(kdf::scrypt(b"", b"", 16, 1, 1, 0, &mut [0; 16]).is_err());
}

#[test]
fn cmac_names_and_lengths_are_validated() {
    assert!(CmacCipher::from_cbc_name("AES-128-GCM").is_err());
    assert!(Cmac::new(CmacCipher::Aes128, &[]).is_err());
    assert!(Cmac::new(CmacCipher::Aes128, &[0; 15]).is_err());
    for (name, size) in [
        ("DES-CBC", 8),
        ("CAMELLIA-128-CBC", 16),
        ("CAMELLIA-192-CBC", 24),
        ("CAMELLIA-256-CBC", 32),
        ("SM4-CBC", 16),
        ("SEED-CBC", 16),
        ("BF-CBC", 16),
        ("CAST5-CBC", 16),
        ("IDEA-CBC", 16),
        ("RC2-CBC", 16),
    ] {
        let cipher = CmacCipher::from_cbc_name(name).unwrap();
        // Availability varies by backend and provider policy. Where supported,
        // copying a partially updated MAC must preserve its result.
        if let Ok(mut mac) = Cmac::new(cipher, &vec![0; size]) {
            mac.update(b"message").unwrap();
            assert_eq!(
                mac.try_clone().unwrap().finish().unwrap(),
                mac.finish().unwrap()
            );
        }
    }
}

#[test]
fn runtime_information_rng_and_error_display() {
    assert!(!runtime::compiled_version_text().is_empty());
    assert!(!runtime::version_text().is_empty());
    assert!(runtime::version_number() > 0);
    rand::mix_additional_input(b"untrusted supplemental input").unwrap();
    assert!(rand::is_ready().unwrap());
    let mut first = [0; 32];
    let mut second = [0; 32];
    rand::fill(&mut first).unwrap();
    rand::fill_private(&mut second).unwrap();
    assert_ne!(first, second);
    assert!(!openssl_bridge::constant_time_eq(b"a", b"ab"));
    #[cfg(backend = "openssl")]
    assert_eq!(
        runtime::require_fips_enabled().is_ok(),
        runtime::is_fips_enabled()
    );
    for error in [
        Error::InvalidInput("input"),
        Error::InvalidState("state"),
        Error::Unsupported("unsupported"),
    ] {
        assert!(!error.to_string().is_empty());
        for wrapped in [
            Pkcs12Error::Encoding(error.clone()),
            Pkcs12Error::PasswordOrData(error.clone()),
            Pkcs12Error::Output(error.clone()),
        ] {
            assert!(wrapped.to_string().contains(&error.to_string()));
        }
    }
}
