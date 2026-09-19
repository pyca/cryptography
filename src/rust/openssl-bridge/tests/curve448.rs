#![cfg(backend = "openssl")]
use openssl_bridge::curve448::{Ed448SigningKey, X448PublicKey, X448SecretKey};
fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
}
#[test]
fn ed448_rfc8032_empty_message() {
    let seed = hex::<57>("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
    let key = Ed448SigningKey::from_seed(&seed).unwrap();
    assert_eq!(key.to_seed().unwrap().as_ref(), seed);
    let public = key.verifying_key().unwrap();
    assert_eq!(public.to_bytes().unwrap(), hex::<57>("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"));
    let signature = key.sign(b"").unwrap();
    assert_eq!(signature, hex::<114>("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600"));
    assert!(public.verify(b"", &signature).unwrap());
    assert!(!public.verify(b"wrong", &signature).unwrap());
    assert!(!public.verify(b"", &signature[..113]).unwrap());
    let mut invalid = signature;
    invalid[50] ^= 1;
    assert!(!public.verify(b"", &invalid).unwrap());
}
#[test]
fn x448_rfc7748_and_small_order_rejection() {
    let key = X448SecretKey::from_bytes(&hex::<56>("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3")).unwrap();
    let peer = X448PublicKey::from_bytes(&hex::<56>("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086")).unwrap();
    assert_eq!(key.exchange(&peer).unwrap().as_ref(), hex::<56>("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"));
    for bytes in [[0; 56], {
        let mut b = [0; 56];
        b[0] = 1;
        b
    }] {
        let low_order = X448PublicKey::from_bytes(&bytes).unwrap();
        assert!(key.exchange(&low_order).is_err());
    }
    let a = X448SecretKey::generate().unwrap();
    let b = X448SecretKey::generate().unwrap();
    assert_eq!(
        a.exchange(&b.public_key().unwrap()).unwrap().as_ref(),
        b.exchange(&a.public_key().unwrap()).unwrap().as_ref()
    );
}
