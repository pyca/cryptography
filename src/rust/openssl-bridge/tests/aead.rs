use openssl_bridge::aead::{Algorithm, Key};

#[test]
fn gcm_nist_sp800_38d_known_answer() {
    let key = Key::new(Algorithm::Aes128Gcm, &[0; 16]).unwrap();
    let mut ciphertext = [0; 16];
    let mut tag = [0; 16];
    key.seal_into(&[0; 12], &[], &[0; 16], &mut ciphertext, &mut tag)
        .unwrap();
    assert_eq!(
        ciphertext,
        [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78
        ]
    );
    assert_eq!(
        tag,
        [
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
            0xbd, 0xdf
        ]
    );
}

#[test]
fn gcm_empty_message_known_answer() {
    let key = Key::new(Algorithm::Aes128Gcm, &[0; 16]).unwrap();
    let mut tag = [0; 16];
    key.seal_into(&[0; 12], &[], &[], &mut [], &mut tag)
        .unwrap();
    assert_eq!(
        tag,
        [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
            0x45, 0x5a
        ]
    );
    key.open_into(&[0; 12], &[], &[], &tag, &mut []).unwrap();
}

#[test]
fn every_supported_aead_authenticates_before_releasing_plaintext() {
    use Algorithm::*;
    assert!(Aes128Gcm.is_available());
    assert!(ChaCha20Poly1305.is_available());
    for algorithm in [
        Aes128Gcm,
        Aes192Gcm,
        Aes256Gcm,
        Aes128Ccm,
        Aes192Ccm,
        Aes256Ccm,
        Aes128Ocb,
        Aes192Ocb,
        Aes256Ocb,
        Aes128Siv,
        Aes192Siv,
        Aes256Siv,
        Aes128GcmSiv,
        Aes192GcmSiv,
        Aes256GcmSiv,
        ChaCha20Poly1305,
    ] {
        if !algorithm.is_available() {
            continue;
        }
        let siv = matches!(algorithm, Aes128Siv | Aes192Siv | Aes256Siv);
        let nonce = if siv { vec![] } else { vec![0x7F; 12] };
        let key = Key::new(algorithm, &vec![0x42; algorithm.key_size()]).unwrap();
        for length in [1, 15, 16, 17, 31, 32, 33, 127] {
            let plaintext = vec![0x28; length];
            let mut ciphertext = vec![0; length];
            let mut tag = [0; 16];
            key.seal_into(
                &nonce,
                &[b"associated"],
                &plaintext,
                &mut ciphertext,
                &mut tag,
            )
            .expect(&format!("{algorithm:?} encryption"));
            let mut output = vec![0xA5; length + 32];
            key.open_into(
                &nonce,
                &[b"associated"],
                &ciphertext,
                &tag,
                &mut output[..length],
            )
            .expect(&format!("{algorithm:?} decryption"));
            assert_eq!(&output[..length], &plaintext);
            assert_eq!(&output[length..], &[0xA5; 32]);
            for byte in 0..tag.len() {
                let mut invalid = tag;
                invalid[byte] ^= 1;
                output.fill(0xA5);
                assert!(
                    key.open_into(
                        &nonce,
                        &[b"associated"],
                        &ciphertext,
                        &invalid,
                        &mut output[..length]
                    )
                    .is_err(),
                    // Failure-only assertion diagnostic; the authentication and output-
                    // preservation checks remain covered.
                    // NO-COVERAGE-START
                    "{algorithm:?} accepted bad tag"
                );
                // NO-COVERAGE-END
                assert!(
                    output.iter().all(|&b| b == 0xA5),
                    // Failure-only assertion diagnostic; the authentication and output-
                    // preservation checks remain covered.
                    // NO-COVERAGE-START
                    "{algorithm:?} released unauthenticated output"
                );
                // NO-COVERAGE-END
            }
            assert!(key
                .open_into(
                    &nonce,
                    &[b"different"],
                    &ciphertext,
                    &tag,
                    &mut output[..length]
                )
                .is_err());
            assert!(output.iter().all(|&b| b == 0xA5));
        }
        if !siv {
            let mut tag = [0; 16];
            key.seal_into(&nonce, &[], &[], &mut [], &mut tag)
                .expect(&format!("{algorithm:?} empty encryption"));
            key.open_into(&nonce, &[], &[], &tag, &mut [])
                .expect(&format!("{algorithm:?} empty decryption"));
            tag[0] ^= 1;
            assert!(key.open_into(&nonce, &[], &[], &tag, &mut []).is_err());
        }
    }
}

#[test]
fn ccm_nonce_length_bounds_payload_and_tag_configuration() {
    if !Algorithm::Aes128Ccm.is_available() {
        return;
    }
    for size in [4, 6, 8, 10, 12, 14, 16] {
        let key = Key::ccm(&[0; 16], size).unwrap();
        let mut tag = vec![0; size];
        let mut ciphertext = vec![0; 65535];
        let mut output = vec![0; 65535];
        key.seal_into(
            &[0; 13],
            &[b"a"],
            &vec![0xA5; 65535],
            &mut ciphertext,
            &mut tag,
        )
        .unwrap();
        key.open_into(&[0; 13], &[b"a"], &ciphertext, &tag, &mut output)
            .unwrap();
        assert!(output.iter().all(|&b| b == 0xA5));
        assert!(key
            .seal_into(
                &[0; 13],
                &[],
                &vec![0; 65536],
                &mut vec![0; 65536],
                &mut tag
            )
            .is_err());
    }
    for size in [0, 1, 3, 5, 7, 9, 11, 13, 15, 17] {
        assert!(Key::ccm(&[0; 16], size).is_err());
    }
}

#[test]
fn siv_preserves_associated_data_component_boundaries() {
    if !Algorithm::Aes128Siv.is_available() {
        return;
    }
    let key = Key::new(Algorithm::Aes128Siv, &[0; 32]).unwrap();
    let mut ciphertext = [0; 9];
    let mut tag = [0; 16];
    let mut output = [0xA5; 9];
    key.seal_into(
        &[],
        &[b"one", b"two"],
        b"plaintext",
        &mut ciphertext,
        &mut tag,
    )
    .unwrap();
    assert!(key
        .open_into(&[], &[b"onetwo"], &ciphertext, &tag, &mut output)
        .is_err());
    assert_eq!(output, [0xA5; 9]);
    key.open_into(&[], &[b"one", b"two"], &ciphertext, &tag, &mut output)
        .unwrap();
    assert_eq!(&output, b"plaintext");
}
