// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::HashSet;

use once_cell::sync::Lazy;

use cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, RsaPssParameters, PSS_SHA256_HASH_ALG,
    PSS_SHA256_MASK_GEN_ALG, PSS_SHA384_HASH_ALG, PSS_SHA384_MASK_GEN_ALG, PSS_SHA512_HASH_ALG,
    PSS_SHA512_MASK_GEN_ALG,
};

pub static WEBPKI_PERMITTED_ALGORITHMS: Lazy<HashSet<AlgorithmIdentifier<'_>>> = Lazy::new(|| {
    HashSet::from([
        // RSASSA‐PKCS1‐v1_5 with SHA‐256
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaWithSha256(Some(())),
        },
        // RSASSA‐PKCS1‐v1_5 with SHA‐384
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaWithSha384(Some(())),
        },
        // RSASSA‐PKCS1‐v1_5 with SHA‐512
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaWithSha512(Some(())),
        },
        // RSASSA‐PSS with SHA‐256, MGF‐1 with SHA‐256, and a salt length of 32 bytes
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
                hash_algorithm: PSS_SHA256_HASH_ALG,
                mask_gen_algorithm: PSS_SHA256_MASK_GEN_ALG,
                salt_length: 32,
                _trailer_field: 1,
            }))),
        },
        // RSASSA‐PSS with SHA‐384, MGF‐1 with SHA‐384, and a salt length of 48 bytes
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
                hash_algorithm: PSS_SHA384_HASH_ALG,
                mask_gen_algorithm: PSS_SHA384_MASK_GEN_ALG,
                salt_length: 48,
                _trailer_field: 1,
            }))),
        },
        // RSASSA‐PSS with SHA‐512, MGF‐1 with SHA‐512, and a salt length of 64 bytes
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
                hash_algorithm: PSS_SHA512_HASH_ALG,
                mask_gen_algorithm: PSS_SHA512_MASK_GEN_ALG,
                salt_length: 64,
                _trailer_field: 1,
            }))),
        },
        // For P-256: the signature MUST use ECDSA with SHA‐256
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::EcDsaWithSha256(None),
        },
        // For P-384: the signature MUST use ECDSA with SHA‐384
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::EcDsaWithSha384(None),
        },
        // For P-521: the signature MUST use ECDSA with SHA‐512
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::EcDsaWithSha512(None),
        },
    ])
});

#[cfg(test)]
mod tests {
    use super::WEBPKI_PERMITTED_ALGORITHMS;

    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    #[test]
    fn test_webpki_permitted_algorithms_canonical_encodings() {
        let mut expected_encodings: Vec<_> = vec![
            // RSASSA‐PKCS1‐v1_5 with SHA‐256
            decode_hex("300d06092a864886f70d01010b0500"),
            // RSASSA‐PKCS1‐v1_5 with SHA‐384
            decode_hex("300d06092a864886f70d01010c0500"),
            // RSASSA‐PKCS1‐v1_5 with SHA‐512
            decode_hex("300d06092a864886f70d01010d0500"),
            // RSASSA‐PSS with SHA‐256, MGF‐1 with SHA‐256, and a salt length of 32 bytes
            decode_hex("304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120"),
            // RSASSA‐PSS with SHA‐384, MGF‐1 with SHA‐384, and a salt length of 48 bytes
            decode_hex("304106092a864886f70d01010a3034a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130"),
            // RSASSA‐PSS with SHA‐512, MGF‐1 with SHA‐512, and a salt length of 64 bytes
            decode_hex("304106092a864886f70d01010a3034a00f300d06096086480165030402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140"),
            // ECDSA: P-256 with SHA256
            decode_hex("300a06082a8648ce3d040302"),
            // ECDSA: P-384 with SHA384
            decode_hex("300a06082a8648ce3d040303"),
            // ECDSA: P-521 with SHA512
            decode_hex("300a06082a8648ce3d040304"),
        ];
        expected_encodings.sort();

        let mut actual_encodings: Vec<_> = WEBPKI_PERMITTED_ALGORITHMS
            .iter()
            .map(|ai| asn1::write_single(ai).unwrap())
            .collect();
        actual_encodings.sort();

        for (exp, act) in expected_encodings.iter().zip(actual_encodings.iter()) {
            assert_eq!(act, exp);
        }
    }
}
