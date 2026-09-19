#![cfg(openssl_320)]
use openssl_bridge::argon2::{Parameters, Variant};
use std::num::NonZeroU32;

#[test]
fn rfc9106_vectors_with_secret_and_associated_data() {
    let params =
        Parameters::new(NonZeroU32::new(3).unwrap(), NonZeroU32::new(4).unwrap(), 32).unwrap();
    // RFC 9106 sections 5.1, 5.2, and 5.3. All use four lanes; the wrapper
    // computes the same result without changing the global thread pool.
    for (variant, expected) in [
        (
            Variant::D,
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
        ),
        (
            Variant::I,
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
        ),
        (
            Variant::Id,
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
        ),
    ] {
        let mut output = [0; 32];
        params
            .derive_into(
                variant,
                &[1; 32],
                &[2; 16],
                Some(&[4; 12]),
                Some(&[3; 8]),
                &mut output,
            )
            .unwrap();
        let expected: Vec<_> = (0..expected.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&expected[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(output.as_slice(), expected);
    }
}

#[test]
fn work_and_length_bounds() {
    let one = NonZeroU32::new(1).unwrap();
    assert!(Parameters::new(one, one, 7).is_err());
    assert!(Parameters::new(one, NonZeroU32::new(1 << 24).unwrap(), u32::MAX).is_err());
    let params = Parameters::new(one, one, 8).unwrap();
    assert!(params
        .derive_into(Variant::Id, b"", b"short", None, None, &mut [0; 32])
        .is_err());
    assert!(params
        .derive_into(Variant::Id, b"", b"saltsalt", None, None, &mut [0; 3])
        .is_err());
}
