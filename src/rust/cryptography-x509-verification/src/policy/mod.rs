// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

mod extension;

use std::collections::HashSet;
use std::ops::Range;
use std::sync::Arc;

use asn1::ObjectIdentifier;
use cryptography_key_parsing::rsa::Pkcs1RsaPublicKey;
use cryptography_x509::certificate::Certificate;
use cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, EcParameters, RsaPssParameters, Time,
    PSS_SHA256_HASH_ALG, PSS_SHA256_MASK_GEN_ALG, PSS_SHA384_HASH_ALG, PSS_SHA384_MASK_GEN_ALG,
    PSS_SHA512_HASH_ALG, PSS_SHA512_MASK_GEN_ALG,
};
use cryptography_x509::extensions::{BasicConstraints, Extensions, SubjectAlternativeName};
use cryptography_x509::name::GeneralName;
use cryptography_x509::oid::{
    BASIC_CONSTRAINTS_OID, EC_SECP256R1, EC_SECP384R1, EC_SECP521R1, EKU_CLIENT_AUTH_OID,
    EKU_SERVER_AUTH_OID,
};
use once_cell::sync::Lazy;

use crate::ops::CryptoOps;
use crate::policy::extension::{ca, common, ee, Criticality, ExtensionPolicy, ExtensionValidator};
use crate::types::{DNSName, DNSPattern, IPAddress};
use crate::{ValidationError, ValidationErrorKind, ValidationResult, VerificationCertificate};

// RSA key constraints, as defined in CA/B 6.1.5.
static WEBPKI_MINIMUM_RSA_MODULUS: usize = 2048;

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
pub static WEBPKI_PERMITTED_SPKI_ALGORITHMS: Lazy<Arc<HashSet<AlgorithmIdentifier<'_>>>> =
    Lazy::new(|| {
        Arc::new(HashSet::from([
            SPKI_RSA.clone(),
            SPKI_SECP256R1.clone(),
            SPKI_SECP384R1.clone(),
            SPKI_SECP521R1.clone(),
        ]))
    });

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
        _trailer_field: None,
    }))),
});

// RSASSA‐PSS with SHA‐384, MGF‐1 with SHA‐384, and a salt length of 48 bytes
static RSASSA_PSS_SHA384: Lazy<AlgorithmIdentifier<'_>> = Lazy::new(|| AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
        hash_algorithm: PSS_SHA384_HASH_ALG,
        mask_gen_algorithm: PSS_SHA384_MASK_GEN_ALG,
        salt_length: 48,
        _trailer_field: None,
    }))),
});

// RSASSA‐PSS with SHA‐512, MGF‐1 with SHA‐512, and a salt length of 64 bytes
static RSASSA_PSS_SHA512: Lazy<AlgorithmIdentifier<'_>> = Lazy::new(|| AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
        hash_algorithm: PSS_SHA512_HASH_ALG,
        mask_gen_algorithm: PSS_SHA512_MASK_GEN_ALG,
        salt_length: 64,
        _trailer_field: None,
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
pub static WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS: Lazy<Arc<HashSet<AlgorithmIdentifier<'_>>>> =
    Lazy::new(|| {
        Arc::new(HashSet::from([
            RSASSA_PKCS1V15_SHA256.clone(),
            RSASSA_PKCS1V15_SHA384.clone(),
            RSASSA_PKCS1V15_SHA512.clone(),
            RSASSA_PSS_SHA256.clone(),
            RSASSA_PSS_SHA384.clone(),
            RSASSA_PSS_SHA512.clone(),
            ECDSA_SHA256.clone(),
            ECDSA_SHA384.clone(),
            ECDSA_SHA512.clone(),
        ]))
    });

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
            (GeneralName::IPAddress(addr), Self::IP(name)) => {
                IPAddress::from_bytes(addr) == Some(*name)
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

/// A `Policy` describes user-configurable aspects of X.509 path validation.
pub struct Policy<'a, B: CryptoOps> {
    pub ops: B,

    /// A top-level constraint on the length of intermediate CA paths
    /// constructed under this policy.
    ///
    /// Per RFC 5280, this limits the length of the non-self-issued intermediate
    /// CA chain, without counting either the leaf or trust anchor.
    pub max_chain_depth: u8,

    /// A subject (i.e. DNS name or other name format) that any EE certificates
    /// validated by this policy must match.
    pub subject: Option<Subject<'a>>,

    /// The validation time. All certificates validated by this policy must
    /// be valid at this time.
    pub validation_time: asn1::DateTime,

    /// An extended key usage that must appear in EEs validated by this policy.
    pub extended_key_usage: ObjectIdentifier,

    /// The minimum RSA modulus, in bits.
    /// This is equivalent to the public key size, e.g. 2048 for an RSA-2048 key.
    pub minimum_rsa_modulus: usize,

    /// The set of permitted public key algorithms, identified by their
    /// algorithm identifiers.
    pub permitted_public_key_algorithms: Arc<HashSet<AlgorithmIdentifier<'a>>>,

    /// The set of permitted signature algorithms, identified by their
    /// algorithm identifiers.
    pub permitted_signature_algorithms: Arc<HashSet<AlgorithmIdentifier<'a>>>,

    ca_extension_policy: ExtensionPolicy<B>,
    ee_extension_policy: ExtensionPolicy<B>,
}

impl<'a, B: CryptoOps> Policy<'a, B> {
    fn new(
        ops: B,
        subject: Option<Subject<'a>>,
        time: asn1::DateTime,
        max_chain_depth: Option<u8>,
        extended_key_usage: ObjectIdentifier,
    ) -> Self {
        Self {
            ops,
            max_chain_depth: max_chain_depth.unwrap_or(DEFAULT_MAX_CHAIN_DEPTH),
            subject,
            validation_time: time,
            extended_key_usage,
            minimum_rsa_modulus: WEBPKI_MINIMUM_RSA_MODULUS,
            permitted_public_key_algorithms: Arc::clone(&*WEBPKI_PERMITTED_SPKI_ALGORITHMS),
            permitted_signature_algorithms: Arc::clone(&*WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS),
            ca_extension_policy: ExtensionPolicy {
                // 5280 4.2.2.1: Authority Information Access
                authority_information_access: ExtensionValidator::maybe_present(
                    Criticality::NonCritical,
                    Some(common::authority_information_access),
                ),
                // 5280 4.2.1.1: Authority Key Identifier
                authority_key_identifier: ExtensionValidator::maybe_present(
                    Criticality::NonCritical,
                    Some(ca::authority_key_identifier),
                ),
                // 5280 4.2.1.2: Subject Key Identifier
                // NOTE: CABF requires SKI in CA certificates, but many older CAs lack it.
                // We choose to be permissive here.
                subject_key_identifier: ExtensionValidator::maybe_present(
                    Criticality::NonCritical,
                    None,
                ),
                // 5280 4.2.1.3: Key Usage
                key_usage: ExtensionValidator::present(Criticality::Agnostic, Some(ca::key_usage)),
                subject_alternative_name: ExtensionValidator::maybe_present(
                    Criticality::Agnostic,
                    None,
                ),
                // 5280 4.2.1.9: Basic Constraints
                basic_constraints: ExtensionValidator::present(
                    Criticality::Critical,
                    Some(ca::basic_constraints),
                ),
                // 5280 4.2.1.10: Name Constraints
                // NOTE: MUST be critical in 5280, but CABF relaxes to MAY.
                name_constraints: ExtensionValidator::maybe_present(
                    Criticality::Agnostic,
                    Some(ca::name_constraints),
                ),
                // 5280: 4.2.1.12: Extended Key Usage
                // NOTE: CABF requires EKUs in many non-root CA certs, but validators widely
                // ignore this requirement and treat a missing EKU as "any EKU".
                // We choose to be permissive here.
                extended_key_usage: ExtensionValidator::maybe_present(
                    Criticality::NonCritical,
                    Some(ca::extended_key_usage),
                ),
            },
            ee_extension_policy: ExtensionPolicy {
                // 5280 4.2.2.1: Authority Information Access
                authority_information_access: ExtensionValidator::maybe_present(
                    Criticality::NonCritical,
                    Some(common::authority_information_access),
                ),
                // 5280 4.2.1.1.: Authority Key Identifier
                authority_key_identifier: ExtensionValidator::present(
                    Criticality::NonCritical,
                    None,
                ),
                subject_key_identifier: ExtensionValidator::maybe_present(
                    Criticality::Agnostic,
                    None,
                ),
                // 5280 4.2.1.3: Key Usage
                key_usage: ExtensionValidator::maybe_present(
                    Criticality::Agnostic,
                    Some(ee::key_usage),
                ),
                // CA/B 7.1.2.7.12 Subscriber Certificate Subject Alternative Name
                // This validator handles both client and server cases by only matching against
                // the SAN if the profile contains a subject, which it won't in the client
                // validation case.
                subject_alternative_name: ExtensionValidator::present(
                    Criticality::Agnostic,
                    Some(ee::subject_alternative_name),
                ),
                // 5280 4.2.1.9: Basic Constraints
                basic_constraints: ExtensionValidator::maybe_present(
                    Criticality::Agnostic,
                    Some(ee::basic_constraints),
                ),
                // 5280 4.2.1.10: Name Constraints
                name_constraints: ExtensionValidator::not_present(),
                // CA/B: 7.1.2.7.10: Subscriber Certificate Extended Key Usage
                // NOTE: CABF requires EKUs in EE certs, while RFC 5280 does not.
                extended_key_usage: ExtensionValidator::maybe_present(
                    Criticality::NonCritical,
                    Some(ee::extended_key_usage),
                ),
            },
        }
    }

    /// Create a new policy with suitable defaults for client certification
    /// validation.
    ///
    /// **IMPORTANT**: This is **not** the appropriate API for verifying
    /// website (i.e. server) certificates. For that, you **must** use
    /// [`Policy::server`].
    pub fn client(ops: B, time: asn1::DateTime, max_chain_depth: Option<u8>) -> Self {
        Self::new(
            ops,
            None,
            time,
            max_chain_depth,
            EKU_CLIENT_AUTH_OID.clone(),
        )
    }

    /// Create a new policy with defaults for the server certificate profile
    /// defined in the CA/B Forum's Basic Requirements.
    pub fn server(
        ops: B,
        subject: Subject<'a>,
        time: asn1::DateTime,
        max_chain_depth: Option<u8>,
    ) -> Self {
        Self::new(
            ops,
            Some(subject),
            time,
            max_chain_depth,
            EKU_SERVER_AUTH_OID.clone(),
        )
    }

    fn permits_basic<'chain>(&self, cert: &Certificate<'_>) -> ValidationResult<'chain, (), B> {
        // CA/B 7.1.1:
        // Certificates MUST be of type X.509 v3.
        if cert.tbs_cert.version != 2 {
            return Err(ValidationError::new(ValidationErrorKind::Other(
                "certificate must be an X509v3 certificate".to_string(),
            )));
        }

        // 5280 4.1.1.2 / 4.1.2.3: signatureAlgorithm / TBS Certificate Signature
        // The top-level signatureAlgorithm and TBSCert signature algorithm
        // MUST match.
        if cert.signature_alg != cert.tbs_cert.signature_alg {
            return Err(ValidationError::new(ValidationErrorKind::Other(
                "mismatch between signatureAlgorithm and SPKI algorithm".to_string(),
            )));
        }

        // 5280 4.1.2.2: Serial Number
        // Per 5280: The serial number MUST be a positive integer.
        // In practice, there are a few roots in common trust stores (like certifi)
        // that have `serial == 0`, so we can't enforce this yet.
        let serial = cert.tbs_cert.serial;
        if !(1..=21).contains(&serial.as_bytes().len()) {
            // Conforming CAs MUST NOT use serial numbers longer than 20 octets.
            // NOTE: In practice, this requires us to check for an encoding of
            // 21 octets, since some CAs generate 20 bytes of randomness and
            // then forget to check whether that number would be negative, resulting
            // in a 21-byte encoding.
            return Err(ValidationError::new(ValidationErrorKind::Other(
                "certificate must have a serial between 1 and 20 octets".to_string(),
            )));
        } else if serial.is_negative() {
            return Err(ValidationError::new(ValidationErrorKind::Other(
                "certificate serial number cannot be negative".to_string(),
            )));
        }

        // 5280 4.1.2.4: Issuer
        // The issuer MUST be a non-empty distinguished name.
        if cert.issuer().is_empty() {
            return Err(ValidationError::new(ValidationErrorKind::Other(
                "certificate must have a non-empty Issuer".to_string(),
            )));
        }

        // 5280 4.1.2.5: Validity
        // Validity dates before 2050 MUST be encoded as UTCTime;
        // dates in or after 2050 MUST be encoded as GeneralizedTime.
        let not_before = cert.tbs_cert.validity.not_before.as_datetime();
        let not_after = cert.tbs_cert.validity.not_after.as_datetime();
        permits_validity_date(&cert.tbs_cert.validity.not_before)?;
        permits_validity_date(&cert.tbs_cert.validity.not_after)?;
        if &self.validation_time < not_before || &self.validation_time > not_after {
            return Err(ValidationError::new(ValidationErrorKind::Other(
                "cert is not valid at validation time".to_string(),
            )));
        }

        Ok(())
    }

    /// Checks whether the given CA certificate is compatible with this policy.
    pub(crate) fn permits_ca<'chain>(
        &self,
        cert: &Certificate<'chain>,
        current_depth: u8,
        extensions: &Extensions<'_>,
    ) -> ValidationResult<'chain, (), B> {
        self.permits_basic(cert)?;

        // 5280 4.1.2.6: Subject
        // CA certificates MUST have a subject populated with a non-empty distinguished name.
        // No check required here: `permits_basic` checks that the issuer is non-empty
        // and `ChainBuilder::potential_issuers` enforces subject/issuer matching,
        // meaning that an CA with an empty subject cannot occur in a built chain.

        // NOTE: This conceptually belongs in `valid_issuer`, but is easier
        // to test here. It's also conceptually an extension policy, but
        // requires a bit of extra external state (`current_depth`) that isn't
        // presently convenient to push into that layer.
        //
        // NOTE: BasicConstraints is required via `ca_extension_policies`,
        // so we always take this branch.
        if let Some(bc) = extensions.get_extension(&BASIC_CONSTRAINTS_OID) {
            let bc: BasicConstraints = bc.value()?;

            if bc
                .path_length
                .map_or(false, |len| u64::from(current_depth) > len)
            {
                return Err(ValidationError::new(ValidationErrorKind::Other(
                    "path length constraint violated".to_string(),
                )));
            }
        }

        self.ca_extension_policy.permits(self, cert, extensions)?;

        Ok(())
    }

    /// Checks whether the given EE certificate is compatible with this policy.
    pub(crate) fn permits_ee<'chain>(
        &self,
        cert: &Certificate<'chain>,
        extensions: &Extensions<'_>,
    ) -> ValidationResult<'chain, (), B> {
        self.permits_basic(cert)?;

        self.ee_extension_policy.permits(self, cert, extensions)?;

        Ok(())
    }

    /// Checks whether `issuer` is a valid issuing CA for `child` at a
    /// path-building depth of `current_depth`.
    ///
    /// This checks that `issuer` is permitted under this policy and that
    /// it was used to sign for `child`.
    ///
    /// As a precondition, the caller must have already checked that
    /// `issuer.subject() == child.issuer()`.
    ///
    /// On success, this function returns the new path-building depth. This
    /// may or may not be a higher number than the original depth, depending
    /// on the kind of validation performed (e.g., whether the issuer was
    /// self-issued).
    pub(crate) fn valid_issuer<'chain>(
        &self,
        issuer: &VerificationCertificate<'chain, B>,
        child: &VerificationCertificate<'chain, B>,
        current_depth: u8,
        issuer_extensions: &Extensions<'_>,
    ) -> ValidationResult<'chain, (), B> {
        // The issuer needs to be a valid CA at the current depth.
        self.permits_ca(issuer.certificate(), current_depth, issuer_extensions)
            .map_err(|e| e.set_cert(issuer.clone()))?;

        // CA/B 7.1.3.1 SubjectPublicKeyInfo
        // NOTE: We check the issuer's SPKI here, since the issuer is
        // definitionally a CA and thus subject to CABF key requirements.
        if !self
            .permitted_public_key_algorithms
            .contains(&issuer.certificate().tbs_cert.spki.algorithm)
        {
            return Err(ValidationError::new(ValidationErrorKind::Other(format!(
                "Forbidden public key algorithm: {:?}",
                &issuer.certificate().tbs_cert.spki.algorithm
            ))));
        }

        // CA/B 7.1.3.2 Signature AlgorithmIdentifier
        // NOTE: We check the child's signature here, since the issuer's
        // signature is not necessarily subject to signature checks (e.g.
        // if it's a root). This works out transitively, as any non root-issuer
        // will be checked in its recursive step (where it'll be in the child
        // position).
        if !self
            .permitted_signature_algorithms
            .contains(&child.certificate().signature_alg)
        {
            return Err(ValidationError::new(ValidationErrorKind::Other(format!(
                "Forbidden signature algorithm: {:?}",
                &child.certificate().signature_alg
            ))));
        }

        // We do this before checking the RSA key size so that if parsing the
        // key fails, we get a nice error message.
        let pk = issuer.public_key(&self.ops).map_err(|_| {
            ValidationError::new(ValidationErrorKind::Other(
                "issuer has malformed public key".to_string(),
            ))
        })?;

        // CA/B 6.1.5: Key sizes
        // NOTE: We don't currently enforce that RSA moduli are divisible by 8,
        // since other implementations don't bother.
        let issuer_spki = &issuer.certificate().tbs_cert.spki;
        if matches!(
            issuer_spki.algorithm.params,
            AlgorithmParameters::Rsa(_) | AlgorithmParameters::RsaPss(_)
        ) {
            let rsa_key: Pkcs1RsaPublicKey<'_> =
                asn1::parse_single(issuer_spki.subject_public_key.as_bytes())?;

            if rsa_key.n.as_bytes().len() * 8 < self.minimum_rsa_modulus {
                return Err(ValidationError::new(ValidationErrorKind::Other(
                    "RSA key is too weak".into(),
                )));
            }
        }

        if self.ops.verify_signed_by(child.certificate(), pk).is_err() {
            return Err(ValidationError::new(ValidationErrorKind::Other(
                "signature does not match".to_string(),
            )));
        }

        Ok(())
    }
}

fn permits_validity_date<'chain, B: CryptoOps>(
    validity_date: &Time,
) -> ValidationResult<'chain, (), B> {
    const GENERALIZED_DATE_INVALIDITY_RANGE: Range<u16> = 1950..2050;

    // NOTE: The inverse check on `asn1::UtcTime` is already done for us
    // by the variant's constructor.
    if let Time::GeneralizedTime(_) = validity_date {
        if GENERALIZED_DATE_INVALIDITY_RANGE.contains(&validity_date.as_datetime().year()) {
            return Err(ValidationError::new(ValidationErrorKind::Other(
                "validity dates between 1950 and 2049 must be UtcTime".to_string(),
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use asn1::{DateTime, SequenceOfWriter};
    use cryptography_x509::common::Time;
    use cryptography_x509::extensions::SubjectAlternativeName;
    use cryptography_x509::name::{GeneralName, UnvalidatedIA5String};

    use super::{
        permits_validity_date, ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512, RSASSA_PKCS1V15_SHA256,
        RSASSA_PKCS1V15_SHA384, RSASSA_PKCS1V15_SHA512, RSASSA_PSS_SHA256, RSASSA_PSS_SHA384,
        RSASSA_PSS_SHA512, WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS,
    };
    use crate::certificate::tests::PublicKeyErrorOps;
    use crate::policy::{
        Subject, SPKI_RSA, SPKI_SECP256R1, SPKI_SECP384R1, SPKI_SECP521R1,
        WEBPKI_PERMITTED_SPKI_ALGORITHMS,
    };
    use crate::types::{DNSName, IPAddress};

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
                asn1::write_single(RSASSA_PSS_SHA256.deref()).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS.contains(&RSASSA_PSS_SHA384.deref()));
            let exp_encoding = b"0A\x06\t*\x86H\x86\xf7\r\x01\x01\n04\xa0\x0f0\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\xa1\x1c0\x1a\x06\t*\x86H\x86\xf7\r\x01\x01\x080\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\xa2\x03\x02\x010";
            assert_eq!(
                asn1::write_single(RSASSA_PSS_SHA384.deref()).unwrap(),
                exp_encoding
            );
        }

        {
            assert!(WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS.contains(&RSASSA_PSS_SHA512.deref()));
            let exp_encoding = b"0A\x06\t*\x86H\x86\xf7\r\x01\x01\n04\xa0\x0f0\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\xa1\x1c0\x1a\x06\t*\x86H\x86\xf7\r\x01\x01\x080\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\xa2\x03\x02\x01@";
            assert_eq!(
                asn1::write_single(RSASSA_PSS_SHA512.deref()).unwrap(),
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
    fn test_subject_matches() {
        let domain_sub = Subject::DNS(DNSName::new("test.cryptography.io").unwrap());
        let ip_sub = Subject::IP(IPAddress::from_str("127.0.0.1").unwrap());

        // Single SAN, domain wildcard.
        {
            let domain_gn = GeneralName::DNSName(UnvalidatedIA5String("*.cryptography.io"));
            let san_der = asn1::write_single(&SequenceOfWriter::new([domain_gn])).unwrap();
            let any_cryptography_io =
                asn1::parse_single::<SubjectAlternativeName<'_>>(&san_der).unwrap();

            assert!(domain_sub.matches(&any_cryptography_io));
            assert!(!ip_sub.matches(&any_cryptography_io));
        }

        // Single SAN, IP address.
        {
            let ip_gn = GeneralName::IPAddress(&[127, 0, 0, 1]);
            let san_der = asn1::write_single(&SequenceOfWriter::new([ip_gn])).unwrap();
            let localhost = asn1::parse_single::<SubjectAlternativeName<'_>>(&san_der).unwrap();

            assert!(ip_sub.matches(&localhost));
            assert!(!domain_sub.matches(&localhost));
        }

        // Multiple SANs, both domain wildcard and IP address.
        {
            let domain_gn = GeneralName::DNSName(UnvalidatedIA5String("*.cryptography.io"));
            let ip_gn = GeneralName::IPAddress(&[127, 0, 0, 1]);
            let san_der = asn1::write_single(&SequenceOfWriter::new([domain_gn, ip_gn])).unwrap();

            let any_cryptography_io_or_localhost =
                asn1::parse_single::<SubjectAlternativeName<'_>>(&san_der).unwrap();

            assert!(domain_sub.matches(&any_cryptography_io_or_localhost));
            assert!(ip_sub.matches(&any_cryptography_io_or_localhost));
        }

        // Single SAN, invalid domain pattern.
        {
            let domain_gn = GeneralName::DNSName(UnvalidatedIA5String("*es*.cryptography.io"));
            let san_der = asn1::write_single(&SequenceOfWriter::new([domain_gn])).unwrap();
            let any_cryptography_io =
                asn1::parse_single::<SubjectAlternativeName<'_>>(&san_der).unwrap();

            assert!(!domain_sub.matches(&any_cryptography_io));
        }
    }

    #[test]
    fn test_validity_date() {
        {
            // Pre-2050 date.
            let utc_dt = DateTime::new(1980, 1, 1, 0, 0, 0).unwrap();
            let generalized_dt = utc_dt.clone();
            let utc_validity = Time::UtcTime(asn1::UtcTime::new(utc_dt).unwrap());
            let generalized_validity =
                Time::GeneralizedTime(asn1::X509GeneralizedTime::new(generalized_dt).unwrap());
            assert!(permits_validity_date::<PublicKeyErrorOps>(&utc_validity).is_ok());
            assert!(permits_validity_date::<PublicKeyErrorOps>(&generalized_validity).is_err());
        }
        {
            // 2049 date.
            let utc_dt = DateTime::new(2049, 1, 1, 0, 0, 0).unwrap();
            let generalized_dt = utc_dt.clone();
            let utc_validity = Time::UtcTime(asn1::UtcTime::new(utc_dt).unwrap());
            let generalized_validity =
                Time::GeneralizedTime(asn1::X509GeneralizedTime::new(generalized_dt).unwrap());
            assert!(permits_validity_date::<PublicKeyErrorOps>(&utc_validity).is_ok());
            assert!(permits_validity_date::<PublicKeyErrorOps>(&generalized_validity).is_err());
        }
        {
            // 2050 date.
            let utc_dt = DateTime::new(2050, 1, 1, 0, 0, 0).unwrap();
            let generalized_dt = utc_dt.clone();
            assert!(asn1::UtcTime::new(utc_dt).is_err());
            let generalized_validity =
                Time::GeneralizedTime(asn1::X509GeneralizedTime::new(generalized_dt).unwrap());
            assert!(permits_validity_date::<PublicKeyErrorOps>(&generalized_validity).is_ok());
        }
        {
            // 2051 date.
            let utc_dt = DateTime::new(2051, 1, 1, 0, 0, 0).unwrap();
            let generalized_dt = utc_dt.clone();
            // The `asn1::UtcTime` constructor prevents this.
            assert!(asn1::UtcTime::new(utc_dt).is_err());
            let generalized_validity =
                Time::GeneralizedTime(asn1::X509GeneralizedTime::new(generalized_dt).unwrap());
            assert!(permits_validity_date::<PublicKeyErrorOps>(&generalized_validity).is_ok());
        }
        {
            // Post-2050 date.
            let utc_dt = DateTime::new(3050, 1, 1, 0, 0, 0).unwrap();
            let generalized_dt = utc_dt.clone();
            // The `asn1::UtcTime` constructor prevents this.
            assert!(asn1::UtcTime::new(utc_dt).is_err());
            let generalized_validity =
                Time::GeneralizedTime(asn1::X509GeneralizedTime::new(generalized_dt).unwrap());
            assert!(permits_validity_date::<PublicKeyErrorOps>(&generalized_validity).is_ok());
        }
    }
}
