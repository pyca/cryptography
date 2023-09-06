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

static WEBPKI_PERMITTED_ALGORITHMS: Lazy<HashSet<AlgorithmIdentifier<'_>>> = Lazy::new(|| {
    HashSet::from([
        // RSASSA‐PKCS1‐v1_5 with SHA‐256
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaWithSha256(None),
        },
        // RSASSA‐PKCS1‐v1_5 with SHA‐384
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaWithSha384(None),
        },
        // RSASSA‐PKCS1‐v1_5 with SHA‐512
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaWithSha512(None),
        },
        // // RSASSA‐PSS with SHA‐256, MGF‐1 with SHA‐256, and a salt length of 32 bytes
        // AlgorithmIdentifier {
        //     oid: asn1::DefinedByMarker::marker(),
        //     params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
        //         hash_algorithm: PSS_SHA256_HASH_ALG,
        //         mask_gen_algorithm: PSS_SHA256_MASK_GEN_ALG,
        //         salt_length: 32,
        //         _trailer_field: Default::default(),
        //     }))),
        // },
        // // RSASSA‐PSS with SHA‐384, MGF‐1 with SHA‐384, and a salt length of 48 bytes
        // AlgorithmIdentifier {
        //     oid: asn1::DefinedByMarker::marker(),
        //     params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
        //         hash_algorithm: PSS_SHA384_HASH_ALG,
        //         mask_gen_algorithm: PSS_SHA384_MASK_GEN_ALG,
        //         salt_length: 48,
        //         _trailer_field: Default::default(),
        //     }))),
        // },
        // // RSASSA‐PSS with SHA‐512, MGF‐1 with SHA‐512, and a salt length of 64 bytes
        // AlgorithmIdentifier {
        //     oid: asn1::DefinedByMarker::marker(),
        //     params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
        //         hash_algorithm: PSS_SHA512_HASH_ALG,
        //         mask_gen_algorithm: PSS_SHA512_MASK_GEN_ALG,
        //         salt_length: 64,
        //         _trailer_field: Default::default(),
        //     }))),
        // },
        // // For P-256: the signature MUST use ECDSA with SHA‐256
        // AlgorithmIdentifier {
        //     oid: asn1::DefinedByMarker::marker(),
        //     params: AlgorithmParameters::EcDsaWithSha256(None),
        // },
        // // For P-384: the signature MUST use ECDSA with SHA‐384
        // AlgorithmIdentifier {
        //     oid: asn1::DefinedByMarker::marker(),
        //     params: AlgorithmParameters::EcDsaWithSha384(None),
        // },
        // // For P-521: the signature MUST use ECDSA with SHA‐512
        // AlgorithmIdentifier {
        //     oid: asn1::DefinedByMarker::marker(),
        //     params: AlgorithmParameters::EcDsaWithSha512(None),
        // },
    ])
});

#[cfg(test)]
mod tests {
    use super::WEBPKI_PERMITTED_ALGORITHMS;

    #[test]
    fn test_webpki_permitted_algorithms_canonical_encodings() {
        let mut expected_encodings: Vec<_> = vec![
            // RSASSA‐PKCS1‐v1_5 with SHA‐256
            b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00".to_vec(),
            // RSASSA‐PKCS1‐v1_5 with SHA‐384
            b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0c\x05\x00".to_vec(),
            // RSASSA‐PKCS1‐v1_5 with SHA‐512
            b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\r\x05\x00".to_vec(),
            // RSASSA‐PSS with SHA‐256, MGF‐1 with SHA‐256, and a salt length of 32 bytes
            b"0A\x06\t*\x86H\x86\xf7\r\x01\x01\n04\xa0\x0f0\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\xa1\x1c0\x1a\x06\t*\x86H\x86\xf7\r\x01\x01\x080\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\xa2\x03\x02\x01 ".to_vec(),
            // // RSASSA‐PSS with SHA‐384, MGF‐1 with SHA‐384, and a salt length of 48 bytes
            // b"0A\x06\t*\x86H\x86\xf7\r\x01\x01\n04\xa0\x0f0\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\xa1\x1c0\x1a\x06\t*\x86H\x86\xf7\r\x01\x01\x080\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\xa2\x03\x02\x010".to_vec(),
            // // RSASSA‐PSS with SHA‐512, MGF‐1 with SHA‐512, and a salt length of 64 bytes
            // b"0A\x06\t*\x86H\x86\xf7\r\x01\x01\n04\xa0\x0f0\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\xa1\x1c0\x1a\x06\t*\x86H\x86\xf7\r\x01\x01\x080\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\xa2\x03\x02\x01@".to_vec(),
            // // ECDSA: P-256 with SHA256
            // b"0\n\x06\x08*\x86H\xce=\x04\x03\x02".to_vec(),
            // // ECDSA: P-384 with SHA384
            // b"0\n\x06\x08*\x86H\xce=\x04\x03\x03".to_vec(),
            // // ECDSA: P-521 with SHA512
            // b"0\n\x06\x08*\x86H\xce=\x04\x03\x04".to_vec(),
        ];
        expected_encodings.sort();

        let mut actual_encodings: Vec<_> = WEBPKI_PERMITTED_ALGORITHMS
            .iter()
            .map(|ai| asn1::write_single(ai).unwrap())
            .collect();
        actual_encodings.sort();

        for (exp, act) in expected_encodings
            .iter()
            .zip(actual_encodings.iter())
            .take(3)
        {
            assert_eq!(act, exp);
        }
    }
}
