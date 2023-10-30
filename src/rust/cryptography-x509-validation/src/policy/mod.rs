// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

mod extension;

use std::collections::HashSet;

use asn1::ObjectIdentifier;
use cryptography_x509::certificate::Certificate;
use once_cell::sync::Lazy;

use cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, EcParameters, RsaPssParameters, PSS_SHA256_HASH_ALG,
    PSS_SHA256_MASK_GEN_ALG, PSS_SHA384_HASH_ALG, PSS_SHA384_MASK_GEN_ALG, PSS_SHA512_HASH_ALG,
    PSS_SHA512_MASK_GEN_ALG,
};
use cryptography_x509::extensions::{
    BasicConstraints, DuplicateExtensionsError, ExtendedKeyUsage, Extension, KeyUsage,
    SubjectAlternativeName,
};
use cryptography_x509::name::GeneralName;
use cryptography_x509::oid::{
    AUTHORITY_INFORMATION_ACCESS_OID, AUTHORITY_KEY_IDENTIFIER_OID, BASIC_CONSTRAINTS_OID,
    EC_SECP256R1, EC_SECP384R1, EC_SECP521R1, EKU_SERVER_AUTH_OID, EXTENDED_KEY_USAGE_OID,
    KEY_USAGE_OID, NAME_CONSTRAINTS_OID, POLICY_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID,
    SUBJECT_DIRECTORY_ATTRIBUTES_OID, SUBJECT_KEY_IDENTIFIER_OID,
};

use self::extension::{ca, common, ee, Criticality, ExtensionPolicy};
use crate::certificate::cert_is_self_issued;
use crate::ops::CryptoOps;
use crate::types::{DNSName, DNSPattern, IPAddress};

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

#[derive(Debug, PartialEq, Eq)]
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
    fn subject_alt_name_matches(&self, general_name: &GeneralName<'_>) -> bool {
        match (general_name, self) {
            (GeneralName::DNSName(pattern), Self::DNS(name)) => {
                DNSPattern::new(pattern.0).map_or(false, |p| p.matches(name))
            }
            (GeneralName::IPAddress(addr), Self::IP(name)) => {
                IPAddress::from_bytes(addr).map_or(false, |addr| addr == *name)
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
    ops: B,

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
    pub subject: Option<Subject<'a>>,

    /// The validation time. All certificates validated by this policy must
    /// be valid at this time.
    pub validation_time: asn1::DateTime,

    /// An extended key usage that must appear in EEs validated by this policy.
    pub extended_key_usage: ObjectIdentifier,

    /// The set of permitted public key algorithms, identified by their
    /// algorithm identifiers.
    ///
    /// If not `None`, all certificates validated by this policy MUST
    /// have a public key algorithm in this set.
    ///
    /// If `None`, all public key algorithms are permitted.
    pub permitted_public_key_algorithms: Option<HashSet<AlgorithmIdentifier<'a>>>,

    /// The set of permitted signature algorithms, identified by their
    /// algorithm identifiers.
    ///
    /// If not `None`, all certificates validated by this policy MUST
    /// have a signature algorithm in this set.
    ///
    /// If `None`, all signature algorithms are permitted.
    pub permitted_signature_algorithms: Option<HashSet<AlgorithmIdentifier<'a>>>,

    common_extension_policies: Vec<ExtensionPolicy<B>>,
    ca_extension_policies: Vec<ExtensionPolicy<B>>,
    ee_extension_policies: Vec<ExtensionPolicy<B>>,
}

impl<'a, B: CryptoOps> Policy<'a, B> {
    /// Create a new policy with defaults for the certificate profile defined in
    /// the CA/B Forum's Basic Requirements.
    pub fn new(ops: B, subject: Option<Subject<'a>>, time: asn1::DateTime) -> Self {
        Self {
            ops,
            max_chain_depth: 8,
            subject,
            validation_time: time,
            extended_key_usage: EKU_SERVER_AUTH_OID.clone(),
            permitted_public_key_algorithms: Some(
                WEBPKI_PERMITTED_SPKI_ALGORITHMS
                    .clone()
                    .into_iter()
                    .cloned()
                    .collect(),
            ),
            permitted_signature_algorithms: Some(
                WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS
                    .clone()
                    .into_iter()
                    .cloned()
                    .collect(),
            ),
            common_extension_policies: Vec::from([
                // 5280 4.2.1.8: Subject Directory Attributes
                ExtensionPolicy::maybe_present(
                    SUBJECT_DIRECTORY_ATTRIBUTES_OID,
                    Criticality::NonCritical,
                    None,
                ),
                // 5280 4.2.2.1: Authority Information Access
                ExtensionPolicy::maybe_present(
                    AUTHORITY_INFORMATION_ACCESS_OID,
                    Criticality::NonCritical,
                    Some(common::authority_information_access),
                ),
            ]),
            ca_extension_policies: Vec::from([
                // 5280 4.2.1.1: Authority Key Identifier
                ExtensionPolicy::maybe_present(
                    AUTHORITY_KEY_IDENTIFIER_OID,
                    Criticality::NonCritical,
                    Some(ca::authority_key_identifier),
                ),
                // 5280 4.2.1.2: Subject Key Identifier
                ExtensionPolicy::present(
                    SUBJECT_KEY_IDENTIFIER_OID,
                    Criticality::NonCritical,
                    None,
                ),
                // 5280 4.2.1.3: Key Usage
                ExtensionPolicy::present(KEY_USAGE_OID, Criticality::Agnostic, Some(ca::key_usage)),
                // 5280 4.2.1.9: Basic Constraints
                ExtensionPolicy::present(
                    BASIC_CONSTRAINTS_OID,
                    Criticality::Critical,
                    Some(ca::basic_constraints),
                ),
                // 5280 4.2.1.10: Name Constraints
                ExtensionPolicy::maybe_present(NAME_CONSTRAINTS_OID, Criticality::Critical, None),
                // 5280 4.2.1.10: Policy Constraints
                ExtensionPolicy::maybe_present(POLICY_CONSTRAINTS_OID, Criticality::Critical, None),
            ]),
            ee_extension_policies: Vec::from([
                // 5280 4.2.1.1.: Authority Key Identifier
                ExtensionPolicy::present(
                    AUTHORITY_KEY_IDENTIFIER_OID,
                    Criticality::NonCritical,
                    None,
                ),
                // 5280 4.2.1.3: Key Usage
                ExtensionPolicy::maybe_present(KEY_USAGE_OID, Criticality::Agnostic, None),
                // CA/B 7.1.2.7.12 Subscriber Certificate Subject Alternative Name
                ExtensionPolicy::present(
                    SUBJECT_ALTERNATIVE_NAME_OID,
                    Criticality::Agnostic,
                    Some(ee::subject_alternative_name),
                ),
                // 5280 4.2.1.9: Basic Constraints
                ExtensionPolicy::maybe_present(
                    BASIC_CONSTRAINTS_OID,
                    Criticality::Agnostic,
                    Some(ee::basic_constraints),
                ),
                // 5280 4.2.1.10: Name Constraints
                ExtensionPolicy::not_present(NAME_CONSTRAINTS_OID),
            ]),
        }
    }

    fn permits_basic(&self, cert: &Certificate<'_>) -> Result<(), PolicyError> {
        let extensions = cert.extensions()?;

        // 5280 4.1.1.2 / 4.1.2.3: signatureAlgorithm / TBS Certificate Signature
        // The top-level signatureAlgorithm and TBSCert signature algorithm
        // MUST match.
        if cert.signature_alg != cert.tbs_cert.signature_alg {
            return Err("mismatch between signatureAlgorithm and SPKI algorithm".into());
        }

        // 5280 4.1.2.2: Serial Number
        // Conforming CAs MUST NOT use serial numbers longer than 20 octets.
        // NOTE: In practice, this requires us to check for an encoding of
        // 21 octets, since some CAs generate 20 bytes of randomness and
        // then forget to check whether that number would be negative, resulting
        // in a 21-byte encoding.
        if !(1..=21).contains(&cert.tbs_cert.serial.as_bytes().len()) {
            return Err("certificate must have a serial between 1 and 20 octets".into());
        }

        // 5280 4.1.2.4: Issuer
        // The issuer MUST be a non-empty distinguished name.
        if cert.issuer().is_empty() {
            return Err("certificate must have a non-empty Issuer".into());
        }

        // 5280 4.1.2.5: Validity
        // Validity dates before 2050 MUST be encoded as UTCTime;
        // dates in or after 2050 MUST be encoded as GeneralizedTime.
        // TODO: The existing `tbs_cert.validity` types don't expose this
        // underlying detail. This check has no practical effect on the
        // correctness of the certificate, so it's pretty low priority.
        if &self.validation_time < cert.tbs_cert.validity.not_before.as_datetime()
            || &self.validation_time > cert.tbs_cert.validity.not_after.as_datetime()
        {
            return Err(PolicyError::Other("cert is not valid at validation time"));
        }

        // Extension policy checks.
        for ext_policy in self.common_extension_policies.iter() {
            ext_policy.permits(self, cert, &extensions)?;
        }

        // CA/B 7.1.3.1 SubjectPublicKeyInfo
        if let Some(permitted_public_key_algorithms) = &self.permitted_public_key_algorithms {
            if !permitted_public_key_algorithms.contains(&cert.tbs_cert.spki.algorithm) {
                // TODO: Should probably include the OID here.
                return Err("Forbidden public key algorithm".into());
            }
        }

        // CA/B 7.1.3.2 Signature AlgorithmIdentifier
        if let Some(permitted_signature_algorithms) = &self.permitted_signature_algorithms {
            if !permitted_signature_algorithms.contains(&cert.signature_alg) {
                // TODO: Should probably include the OID here.
                return Err("Forbidden signature algorithm".into());
            }
        }

        // Check that all critical extensions in this certificate are accounted for.
        let critical_extensions = extensions
            .iter()
            .filter(|e| e.critical)
            .map(|e| e.extn_id)
            .collect::<HashSet<_>>();
        let checked_extensions = self
            .common_extension_policies
            .iter()
            .chain(self.ca_extension_policies.iter())
            .chain(self.ee_extension_policies.iter())
            .map(|p| p.oid.clone())
            .collect::<HashSet<_>>();

        if critical_extensions
            .difference(&checked_extensions)
            .next()
            .is_some()
        {
            // TODO: Render the OIDs here.
            return Err("certificate contains unaccounted-for critical extensions".into());
        }

        Ok(())
    }

    fn permits_san(&self, san_ext: Option<Extension<'_>>) -> Result<(), PolicyError> {
        // TODO: Check if the underlying profile requires a SAN here;
        // if it does and `name` is `None`, then fail.

        match (&self.subject, san_ext) {
            // If we're given both an expected name and the cert has a SAN,
            // then we attempt to match them.
            (Some(sub), Some(san)) => {
                let san: SubjectAlternativeName<'_> = san.value()?;
                match sub.matches(&san) {
                    true => Ok(()),
                    false => Err(PolicyError::Other("EE cert has no matching SAN")),
                }
            }
            // If we aren't given a name but the cert contains a SAN,
            // we complain loudly (under the theory that the user has misused
            // our API and actually intended to match against the SAN).
            (None, Some(_)) => Err(PolicyError::Other(
                "EE cert has subjectAltName but no expected name given to match against",
            )),
            // If we're given an expected name but the cert doesn't contain a
            // SAN, we error.
            (Some(_), None) => Err(PolicyError::Other(
                "EE cert has no subjectAltName but expected name given",
            )),
            // No expected name and no SAN, no problem.
            (None, None) => Ok(()),
        }
    }

    fn permits_eku(&self, eku_ext: Option<Extension<'_>>) -> Result<(), PolicyError> {
        if let Some(ext) = eku_ext {
            let mut ekus: ExtendedKeyUsage<'_> = ext.value()?;

            if ekus.any(|eku| eku == self.extended_key_usage) {
                Ok(())
            } else {
                Err(PolicyError::Other("required EKU not found"))
            }
        } else {
            // If our cert doesn't specify an EKU, then we have nothing to check.
            // This is consistent with the CA/B BRs: a root CA MUST NOT contain
            // an EKU extension.
            // See: CA/B Baseline Requirements v2.0.0: 7.1.2.1.2
            Ok(())
        }
    }

    /// Checks whether the given "leaf" certificate is compatible with this policy.
    ///
    /// A "leaf" certificate is just the certificate in the leaf position during
    /// path validation, whether it be a CA or EE. As such, `permits_leaf`
    /// is logically equivalent to `permits_ee(leaf) || permits_ca(leaf)`.
    pub(crate) fn permits_leaf(&self, leaf: &Certificate<'_>) -> Result<(), PolicyError> {
        // NOTE: Avoid refactoring this to `permits_ee() || permits_ca()` or any variation thereof.
        // Code like this will propagate irrelevant error messages out of the API.
        let extensions = leaf.extensions()?;
        if let Some(key_usage) = extensions.get_extension(&KEY_USAGE_OID) {
            let key_usage: KeyUsage<'_> = key_usage.value()?;
            if key_usage.key_cert_sign() {
                return self.permits_ca(leaf);
            }
        }
        self.permits_ee(leaf)
    }

    /// Checks whether the given CA certificate is compatible with this policy.
    pub(crate) fn permits_ca(&self, cert: &Certificate<'_>) -> Result<(), PolicyError> {
        self.permits_basic(cert)?;

        // 5280 4.1.2.6: Subject
        // CA certificates MUST have a subject populated with a non-empty distinguished name.
        if cert.subject().is_empty() {
            return Err("CA certificate must have a non-empty Subject".into());
        }

        // 5280 4.2:
        // CA certificates must contain a few core extensions. This implies
        // that the CA certificate must be a v3 certificate, since earlier
        // versions lack extensions entirely.
        if cert.tbs_cert.version != 2 {
            return Err("CA certificate must be an X509v3 certificate".into());
        }

        let extensions = cert.extensions()?;
        for ext_policy in self.ca_extension_policies.iter() {
            ext_policy.permits(self, cert, &extensions)?;
        }

        // CA certificates must also adhere to the expected EKU.
        self.permits_eku(extensions.get_extension(&EXTENDED_KEY_USAGE_OID))?;

        // TODO: Policy-level checks for EKUs, algorthms, etc.

        Ok(())
    }

    /// Checks whether the given EE certificate is compatible with this policy.
    pub(crate) fn permits_ee(&self, cert: &Certificate<'_>) -> Result<(), PolicyError> {
        self.permits_basic(cert)?;

        let extensions = cert.extensions()?;
        for ext_policy in self.ee_extension_policies.iter() {
            ext_policy.permits(self, cert, &extensions)?;
        }

        // TODO: These should become extension policies.
        self.permits_san(extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID))?;
        self.permits_eku(extensions.get_extension(&EXTENDED_KEY_USAGE_OID))?;

        // TODO: Policy-level checks here for KUs, etc.

        Ok(())
    }

    /// Checks whether `issuer` is a valid issuing CA for `child` at a
    /// path-building depth of `current_depth`.
    ///
    /// This checks that `issuer` is permitted under this policy and that
    /// it was used to sign for `child`.
    ///
    /// On success, this function returns the new path-building depth. This
    /// may or may not be a higher number than the original depth, depending
    /// on the kind of validation performed (e.g., whether the issuer was
    /// self-issued).
    pub(crate) fn valid_issuer(
        &self,
        issuer: &Certificate<'_>,
        child: &Certificate<'_>,
        current_depth: u8,
    ) -> Result<u8, PolicyError> {
        // The issuer needs to be a valid CA.
        self.permits_ca(issuer)?;

        let issuer_extensions = issuer.extensions()?;

        if let Some(bc) = issuer_extensions.get_extension(&BASIC_CONSTRAINTS_OID) {
            let bc: BasicConstraints = bc
                .value()
                .map_err(|_| PolicyError::Other("issuer has malformed basicConstraints"))?;

            // NOTE: `current_depth` starts at 1, indicating the EE cert in the chain.
            // Path length constraints only concern the intermediate portion of a chain,
            // so we have to adjust by 1.
            if bc
                .path_length
                .map_or(false, |len| (current_depth as u64) - 1 > len)
            {
                return Err(PolicyError::Other("path length constraint violated"));
            }
        }

        let pk = self
            .ops
            .public_key(issuer)
            .map_err(|_| PolicyError::Other("issuer has malformed public key"))?;
        if self.ops.verify_signed_by(child, pk).is_err() {
            return Err(PolicyError::Other("signature does not match"));
        }

        // Self-issued issuers don't increase the working depth.
        match cert_is_self_issued(issuer) {
            true => Ok(current_depth),
            false => Ok(current_depth + 1),
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
        policy::{
            Subject, SPKI_RSA, SPKI_SECP256R1, SPKI_SECP384R1, SPKI_SECP521R1,
            WEBPKI_PERMITTED_SPKI_ALGORITHMS,
        },
        types::{DNSName, IPAddress},
    };

    use super::{
        ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512, RSASSA_PKCS1V15_SHA256, RSASSA_PKCS1V15_SHA384,
        RSASSA_PKCS1V15_SHA512, RSASSA_PSS_SHA256, RSASSA_PSS_SHA384, RSASSA_PSS_SHA512,
        WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS,
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
}
