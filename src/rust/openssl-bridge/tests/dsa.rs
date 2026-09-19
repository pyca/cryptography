use openssl_bridge::dsa::{
    Components, ParameterMaterial, Parameters, PrivateKey, PrivateKeyMaterial, PublicKey,
};
#[cfg(not(backend = "boringssl"))]
use openssl_bridge::hash::{self, Algorithm};
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn parts() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (hex("a8f9cd201e5e35d892f85f80e4db2599a5676a3b1d4f190330ed3256b26d0e80a0e49a8fffaaad2a24f472d2573241d4d6d6c7480c80b4c67bb4479c15ada7ea8424d2502fa01472e760241713dab025ae1b02e1703a1435f62ddf4ee4c1b664066eb22f2e3bf28bb70a2a76e4fd5ebe2d1229681b5b06439ac9c7e9d8bde283"),hex("f85f0f83ac4df7ea0cdf8f469bfeeaea14156495"),hex("2b3152ff6c62f14622b8f48e59f8af46883b38e79b8c74deeae9df131f8b856e3ad6c8455dab87cc0da8ac973417ce4f7878557d6cdf40b35b4a0ca3eb310c6a95d68ce284ad4e25ea28591611ee08b8444bd64b25f3f7c572410ddfb39cc728b9c936f85f419129869929cdb909a6a3a99bbe089216368171bd0ba81de4fe33"))
}
#[test]
fn nist_parameters_scalar_and_validation() {
    let (p, q, g) = parts();
    let params = Parameters::from_components(Components {
        p: &p,
        q: &q,
        g: &g,
    })
    .unwrap();
    let key = PrivateKey::from_scalar(
        params.clone(),
        &hex("c53eae6d45323164c7d07af5715703744a63fc3a"),
    )
    .unwrap();
    assert_eq!(key.public_key().public_value(),hex("313fd9ebca91574e1c2eebe1517c57e0c21b0209872140c5328761bbb2450b33f1b18b409ce9ab7c4cd8fda3391e8e34868357c199e16a6b2eba06d6749def791d79e95d3a4d09b24c392ad89dbf100995ae19c01062056bb14bce005e8731efde175f95b975089bdcdaea562b32786d96f5a31aedf75364008ad4fffebb970b"));
    assert!(PrivateKey::from_scalar(params.clone(), &q).is_err());
    assert!(PrivateKey::from_scalar(params.clone(), &[0]).is_err());
    assert!(PrivateKey::from_components(
        params.clone(),
        &hex("c53eae6d45323164c7d07af5715703744a63fc3a"),
        &[1]
    )
    .is_err());
    assert!(PublicKey::from_components(params.clone(), &[1]).is_err());
    assert!(PublicKey::from_components(params, &p).is_err());
    let mut composite = p.clone();
    *composite.last_mut().unwrap() &= 0xfe;
    let material = ParameterMaterial::from_components(Components {
        p: &composite,
        q: &q,
        g: &g,
    })
    .unwrap();
    let invalid=PrivateKeyMaterial::from_components(material,&hex("c53eae6d45323164c7d07af5715703744a63fc3a"),&hex("313fd9ebca91574e1c2eebe1517c57e0c21b0209872140c5328761bbb2450b33f1b18b409ce9ab7c4cd8fda3391e8e34868357c199e16a6b2eba06d6749def791d79e95d3a4d09b24c392ad89dbf100995ae19c01062056bb14bce005e8731efde175f95b975089bdcdaea562b32786d96f5a31aedf75364008ad4fffebb970b")).unwrap();
    assert!(invalid.validate().is_err());
    assert!(invalid.validate().is_err());
}
#[test]
#[cfg(not(backend = "boringssl"))]
fn nist_signature_and_native_generation() {
    let (p, q, g) = parts();
    let params = Parameters::from_components(Components {
        p: &p,
        q: &q,
        g: &g,
    })
    .unwrap();
    let public=PublicKey::from_components(params.clone(),&hex("313fd9ebca91574e1c2eebe1517c57e0c21b0209872140c5328761bbb2450b33f1b18b409ce9ab7c4cd8fda3391e8e34868357c199e16a6b2eba06d6749def791d79e95d3a4d09b24c392ad89dbf100995ae19c01062056bb14bce005e8731efde175f95b975089bdcdaea562b32786d96f5a31aedf75364008ad4fffebb970b")).unwrap();
    let md = Algorithm::from_name("sha1").unwrap();
    let digest=hash::digest(md,&hex("3b46736d559bd4e0c2c1b2553a33ad3c6cf23cac998d3d0c0e8fa4b19bca06f2f386db2dcff9dca4f40ad8f561ffc308b46c5f31a7735b5fa7e0f9e6cb512e63d7eea05538d66a75cd0d4234b5ccf6c1715ccaaf9cdc0a2228135f716ee9bdee7fc13ec27a03a6d11c5c5b3685f51900b1337153bc6c4e8f52920c33fa37f4e7")).unwrap();
    let signature=hex("302d021450ed0e810e3f1c7cb6ac62332058448bd8b284c0021500c6aded17216b46b7e4b6f2a97c1ad7cc3da83fde");
    assert!(public.verify_digest(md, &digest, &signature).unwrap());
    assert!(!public
        .verify_digest(md, &digest, &signature[..signature.len() - 1])
        .unwrap());
    let generated = params.generate_key().unwrap();
    let signature = generated.sign_digest(md, &digest).unwrap();
    assert!(generated
        .public_key()
        .verify_digest(md, &digest, &signature)
        .unwrap());
    assert!(!public.verify_digest(md, &digest, &signature).unwrap());
    assert!(generated.sign_digest(md, &digest[..19]).is_err());
}

#[test]
fn repeated_and_concurrent_imports_still_check_every_component() {
    let (p, q, g) = parts();
    Parameters::from_components(Components {
        p: &p,
        q: &q,
        g: &g,
    })
    .unwrap();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..8 {
                    let mut padded = vec![0, 0];
                    padded.extend_from_slice(&p);
                    let parameters = Parameters::from_components(Components {
                        p: &padded,
                        q: &q,
                        g: &g,
                    })
                    .unwrap();
                    assert_eq!(parameters.components().p, p);
                    // A valid cached group cannot validate changed p, q, or g.
                    let mut bad_p = p.clone();
                    *bad_p.last_mut().unwrap() &= 0xfe;
                    assert!(Parameters::from_components(Components {
                        p: &bad_p,
                        q: &q,
                        g: &g
                    })
                    .is_err());
                    let mut bad_q = q.clone();
                    *bad_q.last_mut().unwrap() &= 0xfe;
                    assert!(Parameters::from_components(Components {
                        p: &p,
                        q: &bad_q,
                        g: &g
                    })
                    .is_err());
                    // p - 1 has order two, not the odd prime subgroup order q.
                    let mut bad_g = p.clone();
                    *bad_g.last_mut().unwrap() -= 1;
                    assert!(Parameters::from_components(Components {
                        p: &p,
                        q: &q,
                        g: &bad_g
                    })
                    .is_err());
                    assert!(PublicKey::from_components(parameters, &[1]).is_err());
                }
            });
        }
    });
}
