//! Keep this as a separate executable: no other test may initialize OpenSSL
//! before the operation under test. LibreSSL requires explicit registration
//! before cipher lookup, unlike the other supported backends.
use openssl_bridge::mac::{Cmac, CmacCipher};

#[test]
fn cmac_is_usable_as_the_first_operation() {
    // NIST SP 800-38B, AES-128 example 1 (empty message).
    let key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let tag = Cmac::new(CmacCipher::Aes128, &key)
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(
        tag,
        [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
            0x67, 0x46,
        ]
    );
}
