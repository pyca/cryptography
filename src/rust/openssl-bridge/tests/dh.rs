use openssl_bridge::dh::{Components, Parameters, PrivateKey, PublicKey};
fn modulus() -> Vec<u8> {
    // RFC 3526 section 3: the 2048-bit MODP group.
    let text = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff";
    text.as_bytes()
        .chunks_exact(2)
        .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn finite_field_exchange_is_padded_and_peer_checked() {
    let p = modulus();
    let mut q = p.clone();
    *q.last_mut().unwrap() -= 1;
    let mut carry = 0;
    for byte in &mut q {
        let next = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = next;
    }
    let params = Parameters::from_components(Components {
        p: &p,
        q: Some(&q),
        g: &[2],
    })
    .unwrap();
    assert_eq!(params.bits(), 2048);
    let alice = PrivateKey::from_scalar(params.clone(), &[2]).unwrap();
    let bob = PrivateKey::from_scalar(params.clone(), &[3]).unwrap();
    assert_eq!(alice.public_key().public_value(), &[4]);
    let a = alice.exchange(&bob.public_key()).unwrap();
    let b = bob.exchange(&alice.public_key()).unwrap();
    let mut expected = vec![0; 256];
    expected[255] = 64;
    assert_eq!(a.as_ref(), expected);
    assert_eq!(a.as_ref(), b.as_ref());
    assert!(PrivateKey::from_scalar(params.clone(), &[0]).is_err());
    assert!(PrivateKey::from_scalar(params.clone(), &p).is_err());
    assert!(PrivateKey::from_components(params.clone(), &[2], &[8]).is_err());
    assert!(PrivateKey::from_components(params.clone(), &[2], &[4]).is_ok());
    let mut last = p.clone();
    *last.last_mut().unwrap() -= 1;
    for public in [&[][..], &[0], &[1], &p, &last] {
        assert!(PublicKey::from_components(params.clone(), public).is_err());
    }
    let random = params.generate_key().unwrap();
    assert_eq!(
        random.exchange(&alice.public_key()).unwrap().as_ref(),
        alice.exchange(&random.public_key()).unwrap().as_ref()
    );
}
#[test]
fn invalid_parameters_are_rejected_before_operations() {
    let mut p = modulus();
    *p.last_mut().unwrap() -= 1;
    assert!(Parameters::from_components(Components {
        p: &p,
        q: None,
        g: &[2]
    })
    .is_err());
    assert!(Parameters::from_components(Components {
        p: &[23],
        q: None,
        g: &[2]
    })
    .is_err());
    let p = modulus();
    for g in [&[0][..], &[1], &p] {
        assert!(Parameters::from_components(Components { p: &p, q: None, g }).is_err());
    }
    assert!(Parameters::from_components(Components {
        p: &p,
        q: Some(&[0]),
        g: &[2]
    })
    .is_err());
    assert!(Parameters::generate(511, 2).is_err());
    assert!(Parameters::generate(1024, 1).is_err());
}

#[test]
fn encoded_components_preserve_roundtrips_but_cannot_skip_validation() {
    use openssl_bridge::dh::{PrivateKeyMaterial, PublicKeyMaterial};
    let p = modulus();
    let mut q = p.clone();
    *q.last_mut().unwrap() -= 1;
    let mut carry = 0;
    for b in &mut q {
        let next = *b & 1;
        *b = (*b >> 1) | (carry << 7);
        carry = next;
    }
    let params = Parameters::from_components(Components {
        p: &p,
        q: Some(&q),
        g: &[2],
    })
    .unwrap();
    let invalid = PrivateKeyMaterial::from_components(params.clone(), &[2], &[1]).unwrap();
    assert_eq!(invalid.scalar(), &[2]);
    assert_eq!(invalid.public_key().public_value(), &[1]);
    assert!(invalid.validate().is_err());
    let peer = PublicKeyMaterial::from_components(params.clone(), &[1]).unwrap();
    assert!(peer.validate().is_err());
    let valid = PrivateKeyMaterial::from_components(params, &[2], &[4]).unwrap();
    assert!(valid.validate().is_ok());
}

#[test]
fn ssh_group14_with_long_private_exponent() {
    let p = modulus();
    // BoringSSL requires the explicit subgroup order for this legacy group.
    let mut q = p.clone();
    *q.last_mut().unwrap() -= 1;
    let mut carry = 0;
    for byte in &mut q {
        let next = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = next;
    }
    let params = Parameters::from_components(Components {
        p: &p,
        q: Some(&q),
        g: &[2],
    })
    .unwrap();
    let scalar = vec![0x99; 256];
    let alice = PrivateKey::from_scalar(params.clone(), &scalar).unwrap();
    let bob = PrivateKey::from_scalar(params, &[3]).unwrap();
    assert_eq!(
        alice.exchange(&bob.public_key()).unwrap().as_ref(),
        bob.exchange(&alice.public_key()).unwrap().as_ref()
    );
}
