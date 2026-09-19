use openssl_bridge::{
    cipher::{Cipher, Direction, Stream, XtsDataUnit},
    gcm::{GcmCipher, GcmEncrypt, UnverifiedGcmDecrypt},
};

#[test]
fn unpadded_bound_covers_every_partial_block() {
    let data = [9; 64];
    for direction in [Direction::Encrypt, Direction::Decrypt] {
        for split in 0..64 {
            let mut ctx =
                Stream::new(Cipher::Aes128Cbc, direction, &[2; 16], &[3; 16], false).unwrap();
            let mut total = 0;
            for input in [&data[..split], &data[split..]] {
                let capacity = ctx.update_capacity(input.len()).unwrap();
                assert_eq!(capacity, input.len() + 15);
                let mut output = vec![0xA5; capacity + 32];
                let written = ctx.update_into(input, &mut output[..capacity]).unwrap();
                assert!(output[capacity..].iter().all(|&b| b == 0xA5));
                total += written;
            }
            assert_eq!(total, 64);
            assert!(ctx.finish().unwrap().is_empty());
        }
    }
}

#[test]
fn reset_nonce_matches_fresh_context_and_checks_lengths() {
    for cipher in [Cipher::Aes128Ctr, Cipher::ChaCha20] {
        if !cipher.is_available() {
            continue;
        }
        let key = vec![
            0x42;
            if matches!(cipher, Cipher::ChaCha20) {
                32
            } else {
                16
            }
        ];
        let mut ctx = Stream::new(cipher, Direction::Encrypt, &key, &[0; 16], false).unwrap();
        let mut scratch = [0; 33];
        ctx.update_into(&[1; 33], &mut scratch).unwrap();
        assert!(ctx.reset_nonce(&[0; 15]).is_err());
        ctx.reset_nonce(&[2; 16]).unwrap();
        let mut output = [0; 33];
        ctx.update_into(&[1; 33], &mut output).unwrap();
        let mut fresh = Stream::new(cipher, Direction::Encrypt, &key, &[2; 16], false).unwrap();
        fresh.update_into(&[1; 33], &mut scratch).unwrap();
        assert_eq!(output, scratch);
    }
    let mut cbc = Stream::new(
        Cipher::Aes128Cbc,
        Direction::Encrypt,
        &[0; 16],
        &[0; 16],
        false,
    )
    .unwrap();
    assert!(cbc.reset_nonce(&[0; 16]).is_err());
    assert!(Stream::new(
        Cipher::Aes128Cbc,
        Direction::Encrypt,
        &[0; 15],
        &[0; 16],
        false
    )
    .is_err());
    assert!(Cipher::from_name("AES-128-GCM").is_err());
    assert!(Cipher::from_name("AES-128-CBC-HMAC-SHA256").is_err());
}

#[test]
fn chacha_counter_limit_is_enforced_by_the_safe_wrapper() {
    if !Cipher::ChaCha20.is_available() {
        return;
    }
    let mut nonce = [0; 16];
    nonce[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut ctx = Stream::new(
        Cipher::ChaCha20,
        Direction::Encrypt,
        &[0; 32],
        &nonce,
        false,
    )
    .unwrap();
    assert!(ctx.update_into(&[0; 65], &mut [0; 65]).is_err());
    ctx.update_into(&[0; 64], &mut [0; 64]).unwrap();
    assert!(ctx.update_into(&[0], &mut [0]).is_err());
}

#[test]
fn streaming_gcm_checks_order_bounds_and_authentication() {
    let key = [0; 16];
    let nonce = [1; 12];
    let plaintext = [3; 47];
    let aead =
        openssl_bridge::aead::Key::new(openssl_bridge::aead::Algorithm::Aes128Gcm, &key).unwrap();
    let mut expected = [0; 47];
    let mut tag = [0; 16];
    aead.seal_into(
        &nonce,
        &[b"firstsecond"],
        &plaintext,
        &mut expected,
        &mut tag,
    )
    .unwrap();
    let mut enc = GcmEncrypt::new(GcmCipher::Aes128, &key, &nonce).unwrap();
    enc.authenticate(b"first").unwrap();
    enc.authenticate(b"second").unwrap();
    assert!(enc.update_into(&plaintext, &mut [0; 46]).is_err());
    let mut output = [0xA5; 63];
    enc.update_into(&plaintext[..17], &mut output[..17])
        .unwrap();
    assert!(enc.authenticate(b"too late").is_err());
    enc.update_into(&plaintext[17..], &mut output[17..47])
        .unwrap();
    assert_eq!(&output[..47], &expected);
    assert_eq!(&output[47..], &[0xA5; 16]);
    assert_eq!(enc.finish().unwrap(), tag);
    for tag in [
        tag.to_vec(),
        tag[..8].to_vec(),
        tag[..4].to_vec(),
        tag[..3].to_vec(),
        tag[..2].to_vec(),
        tag[..1].to_vec(),
        vec![0; 16],
        vec![],
        vec![0; 17],
    ] {
        let mut dec = UnverifiedGcmDecrypt::new(GcmCipher::Aes128, &key, &nonce).unwrap();
        dec.authenticate(b"firstsecond").unwrap();
        dec.update_unverified_into(&expected, &mut output[..47])
            .unwrap();
        assert_eq!(&output[..47], &plaintext);
        let valid = matches!(tag.len(), 4 | 8) || (tag.len() == 16 && tag.iter().any(|&b| b != 0));
        assert_eq!(dec.finish(&tag).is_ok(), valid);
    }
}

#[test]
fn xts_requires_one_complete_data_unit_and_distinct_keys() {
    if !XtsDataUnit::is_available(64) {
        return;
    }
    let mut key = [1; 64];
    key[32..].fill(2);
    assert!(XtsDataUnit::new(Direction::Encrypt, &[0; 64], &[0; 16]).is_err());
    for len in [16, 17, 31, 32, 63] {
        let data = vec![3; len];
        let mut encrypted = vec![0xA5; len + 16];
        let mut decrypted = vec![0; len];
        XtsDataUnit::new(Direction::Encrypt, &key, &[0; 16])
            .unwrap()
            .crypt_into(&data, &mut encrypted[..len])
            .unwrap();
        assert_eq!(&encrypted[len..], &[0xA5; 16]);
        XtsDataUnit::new(Direction::Decrypt, &key, &[0; 16])
            .unwrap()
            .crypt_into(&encrypted[..len], &mut decrypted)
            .unwrap();
        assert_eq!(data, decrypted);
    }
    assert!(XtsDataUnit::new(Direction::Encrypt, &key, &[0; 16])
        .unwrap()
        .crypt_into(&[0; 15], &mut [0; 15])
        .is_err());
}

#[test]
fn pristine_key_schedules_produce_independent_cipher_states() {
    use openssl_bridge::cipher::CipherKey;
    let key = CipherKey::new(Cipher::Aes128Cbc, &[3; 16], true).unwrap();
    let mut first = key.start(Direction::Encrypt, &[1; 16]).unwrap();
    let mut second = key.start(Direction::Encrypt, &[2; 16]).unwrap();
    let mut a = [0; 48];
    let mut b = [0; 48];
    let an = first.update_into(&[9; 32], &mut a).unwrap();
    let bn = second.update_into(&[9; 32], &mut b).unwrap();
    a[an..].copy_from_slice(&first.finish().unwrap());
    b[bn..].copy_from_slice(&second.finish().unwrap());
    assert_ne!(a, b);
    for (iv, encrypted) in [([1; 16], a), ([2; 16], b)] {
        let mut decrypt = key.start(Direction::Decrypt, &iv).unwrap();
        let mut output = [0; 64];
        let written = decrypt.update_into(&encrypted, &mut output).unwrap();
        let tail = decrypt.finish().unwrap();
        output[written..written + tail.len()].copy_from_slice(&tail);
        assert_eq!(written + tail.len(), 32);
        assert_eq!(&output[..32], &[9; 32]);
    }
}

#[test]
fn blowfish_ecb_has_no_iv() {
    if !Cipher::BlowfishEcb.is_available() {
        return;
    }
    let mut ctx =
        Stream::new(Cipher::BlowfishEcb, Direction::Encrypt, &[0; 8], &[], false).unwrap();
    let mut output = [0; 16];
    let n = ctx.update_into(&[0; 8], &mut output).unwrap();
    assert_eq!(
        &output[..n],
        &[0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78]
    );
    assert!(ctx.finish().unwrap().is_empty());
}
