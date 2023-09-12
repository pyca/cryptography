// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::HashSet;

use asn1::ObjectIdentifier;
use once_cell::sync::Lazy;

use cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, RsaPssParameters, PSS_SHA256_HASH_ALG,
    PSS_SHA256_MASK_GEN_ALG, PSS_SHA384_HASH_ALG, PSS_SHA384_MASK_GEN_ALG, PSS_SHA512_HASH_ALG,
    PSS_SHA512_MASK_GEN_ALG,
};
use cryptography_x509::extensions::{DuplicateExtensionsError, SubjectAlternativeName};
use cryptography_x509::name::GeneralName;
use cryptography_x509::oid::{
    BASIC_CONSTRAINTS_OID, EKU_SERVER_AUTH_OID, KEY_USAGE_OID, SUBJECT_ALTERNATIVE_NAME_OID,
};

use crate::ops::CryptoOps;
use crate::types::{DNSName, DNSPattern, IPAddress, IPRange};

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
pub static WEBPKI_PERMITTED_ALGORITHMS: Lazy<HashSet<&AlgorithmIdentifier<'_>>> = Lazy::new(|| {
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

pub enum PolicyError {
    Malformed(asn1::ParseError),
    DuplicateExtension(DuplicateExtensionsError),
    Other(&'static str),
}

impl From<asn1::ParseError> for PolicyError {
    fn from(value: asn1::ParseError) -> Self {
        Self::Malformed(value)
    }
}

impl From<DuplicateExtensionsError> for PolicyError {
    fn from(value: DuplicateExtensionsError) -> Self {
        Self::DuplicateExtension(value)
    }
}

impl From<&'static str> for PolicyError {
    fn from(value: &'static str) -> Self {
        Self::Other(value)
    }
}

/// Represents a logical certificate "subject," i.e. a principal matching
/// one of the names listed in a certificate's `subjectAltNames` extension.
pub enum Subject<'a> {
    DNS(DNSName<'a>),
    IP(IPAddress),
}

impl Subject<'_> {
    fn general_name_matches(&self, general_name: &GeneralName<'_>) -> bool {
        match (general_name, self) {
            (GeneralName::DNSName(pattern), Self::DNS(name)) => {
                if let Some(pattern) = DNSPattern::new(pattern.0) {
                    pattern.matches(name)
                } else {
                    false
                }
            }
            (GeneralName::IPAddress(pattern), Self::IP(name)) => {
                if let Some(pattern) = IPRange::from_bytes(pattern) {
                    pattern.matches(name)
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Returns true if any of the names in the given `SubjectAlternativeName`
    /// match this `Subject`.
    pub fn matches(&self, san: SubjectAlternativeName<'_>) -> bool {
        let mut san = san;
        san.any(|gn| self.general_name_matches(&gn))
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
///
/// A policy contains multiple moving parts:
///
/// 1. An inner `Profile`, which specifies the valid "shape" of certificates
///    in this policy (e.g., certificates that must conform to RFC 5280);
/// 2. Additional user-specified constraints, such as restrictions on
///    signature and algorithm types.
pub struct Policy<'a, B: CryptoOps> {
    _ops: B,

    /// The X.509 profile to use in this policy.
    // pub profile: P,

    /// A top-level constraint on the length of paths constructed under
    /// this policy.
    ///
    /// Note that this has different semantics from `pathLenConstraint`:
    /// it controls the *overall* non-self-issued chain length, not the number
    /// of non-self-issued intermediates in the chain.
    pub max_chain_depth: u8,

    /// A subject (i.e. DNS name or other name format) that any EE certificates
    /// validated by this policy must match.
    /// If `None`, the EE certificate must not contain a SAN.
    // TODO: Make this an enum with supported SAN variants.
    pub subject: Option<Subject<'a>>,

    /// The validation time. All certificates validated by this policy must
    /// be valid at this time.
    pub validation_time: asn1::DateTime,

    // NOTE: Like the validation time, this conceptually belongs
    // in the underlying profile.
    /// An extended key usage that must appear in EEs validated by this policy.
    pub extended_key_usage: ObjectIdentifier,

    /// The set of permitted signature algorithms, identified by their
    /// algorithm identifiers.
    ///
    /// If not `None`, all certificates validated by this policy MUST
    /// have a signature algorithm in this set.
    ///
    /// If `None`, all signature algorithms are permitted.
    pub permitted_algorithms: Option<HashSet<AlgorithmIdentifier<'a>>>,

    critical_ca_extensions: HashSet<ObjectIdentifier>,
    critical_ee_extensions: HashSet<ObjectIdentifier>,
}

impl<'a, B: CryptoOps> Policy<'a, B> {
    /// Create a new policy with defaults for the certificate profile defined in
    /// RFC 5280.
    pub fn rfc5280(ops: B, subject: Option<Subject<'a>>, time: asn1::DateTime) -> Self {
        Self {
            _ops: ops,
            max_chain_depth: 8,
            subject,
            validation_time: time,
            extended_key_usage: EKU_SERVER_AUTH_OID.clone(),
            // NOTE: RFC 5280 imposes no signature algorithm restrictions.
            permitted_algorithms: None,
            critical_ca_extensions: RFC5280_CRITICAL_CA_EXTENSIONS.iter().cloned().collect(),
            critical_ee_extensions: RFC5280_CRITICAL_EE_EXTENSIONS.iter().cloned().collect(),
        }
    }

    /// Create a new policy with defaults for the certificate profile defined in
    /// the CA/B Forum's Basic Requirements.
    pub fn webpki(ops: B, subject: Option<Subject<'a>>, time: asn1::DateTime) -> Self {
        Self {
            _ops: ops,
            max_chain_depth: 8,
            subject,
            validation_time: time,
            extended_key_usage: EKU_SERVER_AUTH_OID.clone(),
            permitted_algorithms: Some(
                WEBPKI_PERMITTED_ALGORITHMS
                    .clone()
                    .into_iter()
                    .cloned()
                    .collect(),
            ),
            critical_ca_extensions: RFC5280_CRITICAL_CA_EXTENSIONS.iter().cloned().collect(),
            critical_ee_extensions: RFC5280_CRITICAL_EE_EXTENSIONS.iter().cloned().collect(),
        }
    }
}

impl<'a, B: CryptoOps> Policy<'a, B> {
    /// Inform this policy of an expected critical extension in CA certificates.
    ///
    /// This allows the policy to accept critical extensions that the underlying
    /// profile does not cover. The user is responsible for separately validating
    /// these extensions.
    pub fn assert_critical_ca_extension(mut self, oid: ObjectIdentifier) -> Self {
        self.critical_ca_extensions.insert(oid);
        self
    }

    /// Inform this policy of an expected critical extension in EE certificates.
    ///
    /// This allows the policy to accept critical extensions that the underlying
    /// profile does not cover. The user is responsible for separately validating
    /// these extensions.
    pub fn assert_critical_ee_extension(mut self, oid: ObjectIdentifier) -> Self {
        self.critical_ee_extensions.insert(oid);
        self
    }

    /// Configure this policy's validation time, i.e. the time referenced
    /// for certificate validity period checks.
    pub fn with_validation_time(mut self, time: asn1::DateTime) -> Self {
        self.validation_time = time;
        self
    }

    /// Configure this policy's maximum chain building depth, i.e. the
    /// longest chain that path construction will attempt before giving up.
    pub fn with_max_chain_depth(mut self, depth: u8) -> Self {
        self.max_chain_depth = depth;
        self
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use super::{
        ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512, RSASSA_PKCS1V15_SHA256, RSASSA_PKCS1V15_SHA384,
        RSASSA_PKCS1V15_SHA512, RSASSA_PSS_SHA256, RSASSA_PSS_SHA384, RSASSA_PSS_SHA512,
        WEBPKI_PERMITTED_ALGORITHMS,
    };

    #[test]
    fn test_webpki_permitted_algorithms_canonical_encodings() {
        {
            assert!(WEBPKI_PERMITTED_ALGORITHMS.contains(&RSASSA_PKCS1V15_SHA256));
            let exp_encoding = b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00";
            assert_eq!(
                asn1::write_single(&RSASSA_PKCS1V15_SHA256).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_ALGORITHMS.contains(&RSASSA_PKCS1V15_SHA384));
            let exp_encoding = b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0c\x05\x00";
            assert_eq!(
                asn1::write_single(&RSASSA_PKCS1V15_SHA384).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_ALGORITHMS.contains(&RSASSA_PKCS1V15_SHA512));
            let exp_encoding = b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\r\x05\x00";
            assert_eq!(
                asn1::write_single(&RSASSA_PKCS1V15_SHA512).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_ALGORITHMS.contains(&RSASSA_PSS_SHA256.deref()));
            let exp_encoding = b"0A\x06\t*\x86H\x86\xf7\r\x01\x01\n04\xa0\x0f0\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\xa1\x1c0\x1a\x06\t*\x86H\x86\xf7\r\x01\x01\x080\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\xa2\x03\x02\x01 ";
            assert_eq!(
                asn1::write_single(&RSASSA_PSS_SHA256.deref()).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_ALGORITHMS.contains(&RSASSA_PSS_SHA384.deref()));
            let exp_encoding = b"0A\x06\t*\x86H\x86\xf7\r\x01\x01\n04\xa0\x0f0\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\xa1\x1c0\x1a\x06\t*\x86H\x86\xf7\r\x01\x01\x080\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\xa2\x03\x02\x010";
            assert_eq!(
                asn1::write_single(&RSASSA_PSS_SHA384.deref()).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_ALGORITHMS.contains(&RSASSA_PSS_SHA512.deref()));
            let exp_encoding = b"0A\x06\t*\x86H\x86\xf7\r\x01\x01\n04\xa0\x0f0\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\xa1\x1c0\x1a\x06\t*\x86H\x86\xf7\r\x01\x01\x080\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\xa2\x03\x02\x01@";
            assert_eq!(
                asn1::write_single(&RSASSA_PSS_SHA512.deref()).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_ALGORITHMS.contains(&ECDSA_SHA256));
            let exp_encoding = b"0\n\x06\x08*\x86H\xce=\x04\x03\x02";
            assert_eq!(asn1::write_single(&ECDSA_SHA256).unwrap(), exp_encoding);
        }

        {
            assert!(WEBPKI_PERMITTED_ALGORITHMS.contains(&ECDSA_SHA384));
            let exp_encoding = b"0\n\x06\x08*\x86H\xce=\x04\x03\x03";
            assert_eq!(asn1::write_single(&ECDSA_SHA384).unwrap(), exp_encoding);
        }

        {
            assert!(WEBPKI_PERMITTED_ALGORITHMS.contains(&ECDSA_SHA512));
            let exp_encoding = b"0\n\x06\x08*\x86H\xce=\x04\x03\x04";
            assert_eq!(asn1::write_single(&ECDSA_SHA512).unwrap(), exp_encoding);
        }
    }
}
