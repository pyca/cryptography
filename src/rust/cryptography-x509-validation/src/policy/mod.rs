// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

mod extension;

use std::collections::HashSet;

use asn1::ObjectIdentifier;
use once_cell::sync::Lazy;

use cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, EcParameters, RsaPssParameters, PSS_SHA256_HASH_ALG,
    PSS_SHA256_MASK_GEN_ALG, PSS_SHA384_HASH_ALG, PSS_SHA384_MASK_GEN_ALG, PSS_SHA512_HASH_ALG,
    PSS_SHA512_MASK_GEN_ALG,
};
use cryptography_x509::extensions::SubjectAlternativeName;
use cryptography_x509::name::GeneralName;
use cryptography_x509::oid::{
    BASIC_CONSTRAINTS_OID, EC_SECP256R1, EC_SECP384R1, EC_SECP521R1, EKU_SERVER_AUTH_OID,
    KEY_USAGE_OID, SUBJECT_ALTERNATIVE_NAME_OID,
};

use crate::ops::CryptoOps;
use crate::types::{DNSName, DNSPattern, IPAddress, IPConstraint};

// SubjectPublicKeyInfo AlgorithmIdentifier constants, as defined in CA/B 7.1.3.1.

// RSA
static SPKI_RSA: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Rsa(Some(())),
};

// SECP256R1
static SPKI_SECP256R1: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Ec(EcParameters::NamedCurve(EC_SECP256R1)),
};

// SECP384R1
static SPKI_SECP384R1: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Ec(EcParameters::NamedCurve(EC_SECP384R1)),
};

// SECP521R1
static SPKI_SECP521R1: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Ec(EcParameters::NamedCurve(EC_SECP521R1)),
};

/// Permitted algorithms, from CA/B Forum's Baseline Requirements, section 7.1.3.1 (page 96)
/// https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
pub static WEBPKI_PERMITTED_SPKI_ALGORITHMS: Lazy<HashSet<&AlgorithmIdentifier<'_>>> =
    Lazy::new(|| HashSet::from([&SPKI_RSA, &SPKI_SECP256R1, &SPKI_SECP384R1, &SPKI_SECP521R1]));

// Signature AlgorithmIdentifier constants, as defined in CA/B 7.1.3.2.

// RSASSA‐PKCS1‐v1_5 with SHA‐256
static RSASSA_PKCS1V15_SHA256: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::RsaWithSha256(Some(())),
};

// RSASSA‐PKCS1‐v1_5 with SHA‐384
static RSASSA_PKCS1V15_SHA384: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::RsaWithSha384(Some(())),
};

// RSASSA‐PKCS1‐v1_5 with SHA‐512
static RSASSA_PKCS1V15_SHA512: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::RsaWithSha512(Some(())),
};

// RSASSA‐PSS with SHA‐256, MGF‐1 with SHA‐256, and a salt length of 32 bytes
static RSASSA_PSS_SHA256: Lazy<AlgorithmIdentifier<'_>> = Lazy::new(|| AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
        hash_algorithm: PSS_SHA256_HASH_ALG,
        mask_gen_algorithm: PSS_SHA256_MASK_GEN_ALG,
        salt_length: 32,
        _trailer_field: 1,
    }))),
});

// RSASSA‐PSS with SHA‐384, MGF‐1 with SHA‐384, and a salt length of 48 bytes
static RSASSA_PSS_SHA384: Lazy<AlgorithmIdentifier<'_>> = Lazy::new(|| AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
        hash_algorithm: PSS_SHA384_HASH_ALG,
        mask_gen_algorithm: PSS_SHA384_MASK_GEN_ALG,
        salt_length: 48,
        _trailer_field: 1,
    }))),
});

// RSASSA‐PSS with SHA‐512, MGF‐1 with SHA‐512, and a salt length of 64 bytes
static RSASSA_PSS_SHA512: Lazy<AlgorithmIdentifier<'_>> = Lazy::new(|| AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
        hash_algorithm: PSS_SHA512_HASH_ALG,
        mask_gen_algorithm: PSS_SHA512_MASK_GEN_ALG,
        salt_length: 64,
        _trailer_field: 1,
    }))),
});

// For P-256: the signature MUST use ECDSA with SHA‐256
static ECDSA_SHA256: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::EcDsaWithSha256(None),
};

// For P-384: the signature MUST use ECDSA with SHA‐384
static ECDSA_SHA384: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::EcDsaWithSha384(None),
};

// For P-521: the signature MUST use ECDSA with SHA‐512
static ECDSA_SHA512: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::EcDsaWithSha512(None),
};

/// Permitted algorithms, from CA/B Forum's Baseline Requirements, section 7.1.3.2 (pages 96-98)
/// https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf
pub static WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS: Lazy<HashSet<&AlgorithmIdentifier<'_>>> =
    Lazy::new(|| {
        HashSet::from([
            &RSASSA_PKCS1V15_SHA256,
            &RSASSA_PKCS1V15_SHA384,
            &RSASSA_PKCS1V15_SHA512,
            &RSASSA_PSS_SHA256,
            &RSASSA_PSS_SHA384,
            &RSASSA_PSS_SHA512,
            &ECDSA_SHA256,
            &ECDSA_SHA384,
            &ECDSA_SHA512,
        ])
    });

const RFC5280_CRITICAL_CA_EXTENSIONS: &[asn1::ObjectIdentifier] =
    &[BASIC_CONSTRAINTS_OID, KEY_USAGE_OID];
const RFC5280_CRITICAL_EE_EXTENSIONS: &[asn1::ObjectIdentifier] =
    &[BASIC_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID];

/// A default reasonable maximum chain depth.
///
/// This depth was chosen to balance between common validation lengths
/// (chains in the Web PKI are ordinarily no longer than 2 or 3 intermediates
/// in the longest cases) and support for pathological cases.
///
/// Relatively little prior art for selecting a default depth exists;
/// OpenSSL defaults to a limit of 100, which is far more permissive than
/// necessary.
const DEFAULT_MAX_CHAIN_DEPTH: u8 = 8;

pub enum PolicyError {
    Other(&'static str),
}

/// Represents a logical certificate "subject," i.e. a principal matching
/// one of the names listed in a certificate's `subjectAltNames` extension.
pub enum Subject<'a> {
    DNS(DNSName<'a>),
    IP(IPAddress),
}

impl Subject<'_> {
    fn subject_alt_name_matches(&self, general_name: &GeneralName<'_>) -> bool {
        match (general_name, self) {
            (GeneralName::DNSName(pattern), Self::DNS(name)) => {
                DNSPattern::new(pattern.0).map_or(false, |p| p.matches(name))
            }
            (GeneralName::IPAddress(pattern), Self::IP(name)) => {
                IPConstraint::from_bytes(pattern).map_or(false, |p| p.matches(name))
            }
            _ => false,
        }
    }

    /// Returns true if any of the names in the given `SubjectAlternativeName`
    /// match this `Subject`.
    pub fn matches(&self, san: &SubjectAlternativeName<'_>) -> bool {
        san.clone().any(|gn| self.subject_alt_name_matches(&gn))
    }
}

impl<'a> From<DNSName<'a>> for Subject<'a> {
    fn from(value: DNSName<'a>) -> Self {
        Self::DNS(value)
    }
}

impl From<IPAddress> for Subject<'_> {
    fn from(value: IPAddress) -> Self {
        Self::IP(value)
    }
}

/// A `Policy` describes user-configurable aspects of X.509 path validation.
pub struct Policy<'a, B: CryptoOps> {
    _ops: B,

    /// A top-level constraint on the length of intermediate CA paths
    /// constructed under this policy.
    ///
    /// Per RFC 5280, this limits the length of the non-self-issued intermediate
    /// CA chain, without counting either the leaf or trust anchor.
    pub max_chain_depth: u8,

    /// A subject (i.e. DNS name or other name format) that any EE certificates
    /// validated by this policy must match.
    /// If `None`, the EE certificate must not contain a SAN.
    pub subject: Option<Subject<'a>>,

    /// The validation time. All certificates validated by this policy must
    /// be valid at this time.
    pub validation_time: asn1::DateTime,

    /// An extended key usage that must appear in EEs validated by this policy.
    pub extended_key_usage: ObjectIdentifier,

    /// The set of permitted public key algorithms, identified by their
    /// algorithm identifiers.
    pub permitted_public_key_algorithms: HashSet<AlgorithmIdentifier<'a>>,

    /// The set of permitted signature algorithms, identified by their
    /// algorithm identifiers.
    pub permitted_signature_algorithms: HashSet<AlgorithmIdentifier<'a>>,

    pub critical_ca_extensions: HashSet<ObjectIdentifier>,
    pub critical_ee_extensions: HashSet<ObjectIdentifier>,
}

impl<'a, B: CryptoOps> Policy<'a, B> {
    /// Create a new policy with defaults for the certificate profile defined in
    /// the CA/B Forum's Basic Requirements.
    pub fn new(
        ops: B,
        subject: Option<Subject<'a>>,
        time: asn1::DateTime,
        max_chain_depth: Option<u8>,
    ) -> Self {
        Self {
            _ops: ops,
            max_chain_depth: max_chain_depth.unwrap_or(DEFAULT_MAX_CHAIN_DEPTH),
            subject,
            validation_time: time,
            extended_key_usage: EKU_SERVER_AUTH_OID.clone(),
            permitted_public_key_algorithms: WEBPKI_PERMITTED_SPKI_ALGORITHMS
                .clone()
                .into_iter()
                .cloned()
                .collect(),
            permitted_signature_algorithms: WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS
                .clone()
                .into_iter()
                .cloned()
                .collect(),
            critical_ca_extensions: RFC5280_CRITICAL_CA_EXTENSIONS.iter().cloned().collect(),
            critical_ee_extensions: RFC5280_CRITICAL_EE_EXTENSIONS.iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use asn1::SequenceOfWriter;
    use cryptography_x509::{
        extensions::SubjectAlternativeName,
        name::{GeneralName, UnvalidatedIA5String},
    };

    use crate::{
        ops::tests::NullOps,
        policy::{
            Subject, RFC5280_CRITICAL_CA_EXTENSIONS, RFC5280_CRITICAL_EE_EXTENSIONS, SPKI_RSA,
            SPKI_SECP256R1, SPKI_SECP384R1, SPKI_SECP521R1, WEBPKI_PERMITTED_SPKI_ALGORITHMS,
        },
        types::{DNSName, IPAddress},
    };

    use super::{
        Policy, ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512, RSASSA_PKCS1V15_SHA256,
        RSASSA_PKCS1V15_SHA384, RSASSA_PKCS1V15_SHA512, RSASSA_PSS_SHA256, RSASSA_PSS_SHA384,
        RSASSA_PSS_SHA512, WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS,
    };

    #[test]
    fn test_webpki_permitted_spki_algorithms_canonical_encodings() {
        {
            assert!(WEBPKI_PERMITTED_SPKI_ALGORITHMS.contains(&SPKI_RSA));
            let exp_encoding = b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00";
            assert_eq!(asn1::write_single(&SPKI_RSA).unwrap(), exp_encoding);
        }

        {
            assert!(WEBPKI_PERMITTED_SPKI_ALGORITHMS.contains(&SPKI_SECP256R1));
            let exp_encoding = b"0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07";
            assert_eq!(asn1::write_single(&SPKI_SECP256R1).unwrap(), exp_encoding);
        }

        {
            assert!(WEBPKI_PERMITTED_SPKI_ALGORITHMS.contains(&SPKI_SECP384R1));
            let exp_encoding = b"0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00\"";
            assert_eq!(asn1::write_single(&SPKI_SECP384R1).unwrap(), exp_encoding);
        }

        {
            assert!(WEBPKI_PERMITTED_SPKI_ALGORITHMS.contains(&SPKI_SECP521R1));
            let exp_encoding = b"0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00#";
            assert_eq!(asn1::write_single(&SPKI_SECP521R1).unwrap(), exp_encoding);
        }
    }

    #[test]
    fn test_webpki_permitted_signature_algorithms_canonical_encodings() {
        {
            assert!(WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS.contains(&RSASSA_PKCS1V15_SHA256));
            let exp_encoding = b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00";
            assert_eq!(
                asn1::write_single(&RSASSA_PKCS1V15_SHA256).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS.contains(&RSASSA_PKCS1V15_SHA384));
            let exp_encoding = b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0c\x05\x00";
            assert_eq!(
                asn1::write_single(&RSASSA_PKCS1V15_SHA384).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS.contains(&RSASSA_PKCS1V15_SHA512));
            let exp_encoding = b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\r\x05\x00";
            assert_eq!(
                asn1::write_single(&RSASSA_PKCS1V15_SHA512).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS.contains(&RSASSA_PSS_SHA256.deref()));
            let exp_encoding = b"0A\x06\t*\x86H\x86\xf7\r\x01\x01\n04\xa0\x0f0\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\xa1\x1c0\x1a\x06\t*\x86H\x86\xf7\r\x01\x01\x080\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\xa2\x03\x02\x01 ";
            assert_eq!(
                asn1::write_single(&RSASSA_PSS_SHA256.deref()).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS.contains(&RSASSA_PSS_SHA384.deref()));
            let exp_encoding = b"0A\x06\t*\x86H\x86\xf7\r\x01\x01\n04\xa0\x0f0\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\xa1\x1c0\x1a\x06\t*\x86H\x86\xf7\r\x01\x01\x080\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\xa2\x03\x02\x010";
            assert_eq!(
                asn1::write_single(&RSASSA_PSS_SHA384.deref()).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS.contains(&RSASSA_PSS_SHA512.deref()));
            let exp_encoding = b"0A\x06\t*\x86H\x86\xf7\r\x01\x01\n04\xa0\x0f0\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\xa1\x1c0\x1a\x06\t*\x86H\x86\xf7\r\x01\x01\x080\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\xa2\x03\x02\x01@";
            assert_eq!(
                asn1::write_single(&RSASSA_PSS_SHA512.deref()).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS.contains(&ECDSA_SHA256));
            let exp_encoding = b"0\n\x06\x08*\x86H\xce=\x04\x03\x02";
            assert_eq!(asn1::write_single(&ECDSA_SHA256).unwrap(), exp_encoding);
        }

        {
            assert!(WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS.contains(&ECDSA_SHA384));
            let exp_encoding = b"0\n\x06\x08*\x86H\xce=\x04\x03\x03";
            assert_eq!(asn1::write_single(&ECDSA_SHA384).unwrap(), exp_encoding);
        }

        {
            assert!(WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS.contains(&ECDSA_SHA512));
            let exp_encoding = b"0\n\x06\x08*\x86H\xce=\x04\x03\x04";
            assert_eq!(asn1::write_single(&ECDSA_SHA512).unwrap(), exp_encoding);
        }
    }

    #[test]
    fn test_policy_critical_extensions() {
        let time = asn1::DateTime::new(2023, 9, 12, 1, 1, 1).unwrap();
        let policy = Policy::new(NullOps {}, None, time, None);

        assert_eq!(
            policy.critical_ca_extensions,
            RFC5280_CRITICAL_CA_EXTENSIONS.iter().cloned().collect()
        );
        assert_eq!(
            policy.critical_ee_extensions,
            RFC5280_CRITICAL_EE_EXTENSIONS.iter().cloned().collect()
        );
    }

    #[test]
    fn test_subject_from_impls() {
        assert!(matches!(
            Subject::from(DNSName::new("cryptography.io").unwrap()),
            Subject::DNS(_)
        ));

        assert!(matches!(
            Subject::from(IPAddress::from_str("1.1.1.1").unwrap()),
            Subject::IP(_)
        ));
    }

    #[test]
    fn test_subject_matches() {
        let domain_sub = Subject::from(DNSName::new("test.cryptography.io").unwrap());
        let ip_sub = Subject::from(IPAddress::from_str("127.0.0.1").unwrap());

        // Single SAN, domain wildcard.
        {
            let domain_gn = GeneralName::DNSName(UnvalidatedIA5String("*.cryptography.io"));
            let san_der = asn1::write_single(&SequenceOfWriter::new([domain_gn])).unwrap();
            let any_cryptography_io =
                asn1::parse_single::<SubjectAlternativeName<'_>>(&san_der).unwrap();

            assert!(domain_sub.matches(&any_cryptography_io));
            assert!(!ip_sub.matches(&any_cryptography_io));
        }

        // Single SAN, IP range.
        {
            // 127.0.0.1/24
            let ip_gn = GeneralName::IPAddress(&[127, 0, 0, 1, 255, 255, 255, 0]);
            let san_der = asn1::write_single(&SequenceOfWriter::new([ip_gn])).unwrap();
            let local_24 = asn1::parse_single::<SubjectAlternativeName<'_>>(&san_der).unwrap();

            assert!(ip_sub.matches(&local_24));
            assert!(!domain_sub.matches(&local_24));
        }

        // Multiple SANs, both domain wildcard and IP range.
        {
            let domain_gn = GeneralName::DNSName(UnvalidatedIA5String("*.cryptography.io"));
            let ip_gn = GeneralName::IPAddress(&[127, 0, 0, 1, 255, 255, 255, 0]);
            let san_der = asn1::write_single(&SequenceOfWriter::new([domain_gn, ip_gn])).unwrap();

            let any_cryptography_io_or_local_24 =
                asn1::parse_single::<SubjectAlternativeName<'_>>(&san_der).unwrap();

            assert!(domain_sub.matches(&any_cryptography_io_or_local_24));
            assert!(ip_sub.matches(&any_cryptography_io_or_local_24));
        }

        // Single SAN, invalid domain pattern.
        {
            let domain_gn = GeneralName::DNSName(UnvalidatedIA5String("*es*.cryptography.io"));
            let san_der = asn1::write_single(&SequenceOfWriter::new([domain_gn])).unwrap();
            let any_cryptography_io =
                asn1::parse_single::<SubjectAlternativeName<'_>>(&san_der).unwrap();

            assert!(!domain_sub.matches(&any_cryptography_io));
        }

        // Single SAN, invalid IP range.
        {
            // 127.0.0.1/24
            let ip_gn = GeneralName::IPAddress(&[127, 0, 0, 1, 1, 255, 1, 0]);
            let san_der = asn1::write_single(&SequenceOfWriter::new([ip_gn])).unwrap();
            let local_24 = asn1::parse_single::<SubjectAlternativeName<'_>>(&san_der).unwrap();

            assert!(!ip_sub.matches(&local_24));
        }
    }
}
