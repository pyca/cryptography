use openssl_bridge::{
    cipher::{Cipher, Direction, Stream},
    hash::{self, Algorithm, Hasher},
    mac::Hmac,
    Error,
};

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn sha256_fips_180_4() {
    let sha256 = Algorithm::from_name("SHA256").unwrap();
    assert_eq!(
        hash::digest(sha256, b"abc").unwrap(),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    let mut initial = Hasher::new(sha256).unwrap();
    initial.update(b"a").unwrap();
    let mut copy = initial.try_clone().unwrap();
    initial.update(b"bc").unwrap();
    copy.update(b" different suffix").unwrap();
    assert_eq!(
        initial.finish().unwrap(),
        hash::digest(sha256, b"abc").unwrap()
    );
    assert_eq!(
        copy.finish().unwrap(),
        hash::digest(sha256, b"a different suffix").unwrap()
    );
}

#[test]
fn hmac_rfc4231_case_1() {
    let mut mac = Hmac::new(Algorithm::from_name("SHA256").unwrap(), &[0x0b; 20]).unwrap();
    mac.update(b"Hi ").unwrap();
    let mut copy = mac.try_clone().unwrap();
    mac.update(b"There").unwrap();
    copy.update(b"There").unwrap();
    let expected = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert_eq!(mac.finish().unwrap(), expected);
    assert_eq!(copy.finish().unwrap(), expected);
}

#[test]
fn invalid_algorithm_names_are_errors() {
    assert!(matches!(
        Algorithm::from_name("SHA256\0SHA1"),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        Algorithm::from_name("does-not-exist"),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn aes_cbc_nist_sp800_38a() {
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = hex("000102030405060708090a0b0c0d0e0f");
    let plaintext = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
    let expected = hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2");
    for split in 0..=plaintext.len() {
        let mut stream =
            Stream::new(Cipher::Aes128Cbc, Direction::Encrypt, &key, &iv, false).unwrap();
        let mut result = Vec::new();
        for part in [&plaintext[..split], &plaintext[split..]] {
            let mut out = vec![0; stream.update_capacity(part.len()).unwrap()];
            let len = stream.update_into(part, &mut out).unwrap();
            result.extend_from_slice(&out[..len]);
        }
        result.extend_from_slice(&stream.finish().unwrap());
        assert_eq!(result, expected, "split {split}");
    }
}

#[test]
fn cipher_bounds_checks_leave_canaries_untouched() {
    let mut stream = Stream::new(
        Cipher::Aes128Cbc,
        Direction::Encrypt,
        &[0; 16],
        &[0; 16],
        false,
    )
    .unwrap();
    let mut output = [0x55; 33];
    assert!(stream.update_into(&[0; 16], &mut output[1..16]).is_err());
    assert_eq!(output, [0x55; 33]);
    // A rejected Rust-side input does not modify or poison the native context.
    assert_eq!(stream.update_into(&[0; 16], &mut output[..32]).unwrap(), 16);
    assert_eq!(output[32], 0x55);
    assert!(stream.update_capacity(usize::MAX).is_err());
    assert!(Stream::new(
        Cipher::Aes128Cbc,
        Direction::Encrypt,
        &[0; 15],
        &[0; 16],
        false
    )
    .is_err());
    assert!(Stream::new(
        Cipher::Aes128Cbc,
        Direction::Encrypt,
        &[0; 16],
        &[0; 15],
        false
    )
    .is_err());
}

#[test]
fn cmac_nist_sp800_38b() {
    use openssl_bridge::mac::{Cmac, CmacCipher};
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let mut mac = Cmac::new(CmacCipher::Aes128, &key).unwrap();
    let empty = mac.try_clone().unwrap().finish().unwrap();
    assert_eq!(empty, hex("bb1d6929e95937287fa37d129b756746"));
    mac.update(&hex("6bc1bee22e409f96e93d7e117393172a"))
        .unwrap();
    assert_eq!(
        mac.finish().unwrap(),
        hex("070a16b46b4d4144f79bdd9dd04a287c")
    );
}

#[test]
fn pbkdf2_rfc6070_and_scrypt_rfc7914() {
    use openssl_bridge::kdf;
    let mut output = [0; 20];
    kdf::pbkdf2_hmac(
        Algorithm::from_name("SHA1").unwrap(),
        b"password",
        b"salt",
        1.try_into().unwrap(),
        &mut output,
    )
    .unwrap();
    assert_eq!(
        output.to_vec(),
        hex("0c60c80f961f0e71f3a9b524af6012062fe037a6")
    );
    let mut output = [0; 64];
    if openssl_bridge::BACKEND == openssl_bridge::Backend::LibreSsl {
        assert!(matches!(
            kdf::scrypt(b"", b"", 16, 1, 1, 1024 * 1024, &mut output),
            Err(Error::Unsupported(_))
        ));
        return;
    }
    kdf::scrypt(b"", b"", 16, 1, 1, 1024 * 1024, &mut output).unwrap();
    assert_eq!(output.to_vec(),hex("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"));
    assert!(kdf::scrypt(b"", b"", 3, 1, 1, 1024 * 1024, &mut output).is_err());
}

#[test]
fn ed25519_rfc8032_vector_1() {
    use openssl_bridge::curve25519::{Ed25519SigningKey, Ed25519VerifyingKey};
    let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let key = Ed25519SigningKey::from_seed(seed.as_slice().try_into().unwrap()).unwrap();
    let public = key.verifying_key().unwrap();
    assert_eq!(
        public.to_bytes().unwrap().to_vec(),
        hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    let signature = key.sign(b"").unwrap();
    assert_eq!(signature.to_vec(),hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"));
    assert!(public.verify(b"", &signature).unwrap());
    assert!(!public.verify(b"x", &signature).unwrap());
    assert!(!public.verify(b"", &signature[..63]).unwrap());
    let restored = Ed25519VerifyingKey::from_bytes(&public.to_bytes().unwrap()).unwrap();
    assert!(restored.verify(b"", &signature).unwrap());
    assert_eq!(key.to_seed().unwrap().as_ref(), seed);
}

#[test]
fn x25519_rfc7748_vector() {
    use openssl_bridge::curve25519::{X25519PublicKey, X25519SecretKey};
    let alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let alice = X25519SecretKey::from_bytes(alice.as_slice().try_into().unwrap()).unwrap();
    let bob = X25519SecretKey::from_bytes(bob.as_slice().try_into().unwrap()).unwrap();
    assert_eq!(
        alice.public_key().unwrap().to_bytes().unwrap().to_vec(),
        hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    let shared = alice.exchange(&bob.public_key().unwrap()).unwrap();
    assert_eq!(
        shared.as_ref(),
        hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    );
    assert_eq!(
        shared.as_ref(),
        bob.exchange(&alice.public_key().unwrap()).unwrap().as_ref()
    );
    assert!(alice
        .exchange(&X25519PublicKey::from_bytes(&[0; 32]).unwrap())
        .is_err());
}

#[test]
fn cbc_padding_roundtrips_every_partial_block_split() {
    for length in 0..64 {
        let input = vec![0x55; length];
        let mut encrypt = Stream::new(
            Cipher::Aes128Cbc,
            Direction::Encrypt,
            &[0; 16],
            &[0; 16],
            true,
        )
        .unwrap();
        let mut encrypted = vec![0; encrypt.update_capacity(input.len()).unwrap()];
        let n = encrypt.update_into(&input, &mut encrypted).unwrap();
        encrypted.truncate(n);
        encrypted.extend_from_slice(&encrypt.finish().unwrap());
        for split in 0..=encrypted.len() {
            let mut decrypt = Stream::new(
                Cipher::Aes128Cbc,
                Direction::Decrypt,
                &[0; 16],
                &[0; 16],
                true,
            )
            .unwrap();
            let mut plaintext = Vec::new();
            for part in [&encrypted[..split], &encrypted[split..]] {
                let capacity = decrypt.update_capacity(part.len()).unwrap();
                let mut output = vec![0x77; capacity + 2];
                let written = decrypt
                    .update_into(part, &mut output[1..=capacity])
                    .unwrap();
                assert_eq!(output[0], 0x77);
                assert_eq!(output[capacity + 1], 0x77);
                plaintext.extend_from_slice(&output[1..=written]);
            }
            plaintext.extend_from_slice(&decrypt.finish().unwrap());
            assert_eq!(plaintext, input, "length {length}, split {split}");
        }
    }
}
