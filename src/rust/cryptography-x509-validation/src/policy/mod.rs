// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::HashSet;

use asn1::ObjectIdentifier;
use cryptography_x509::certificate::Certificate;
use cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, RsaPssParameters, PSS_SHA256_HASH_ALG,
    PSS_SHA256_MASK_GEN_ALG, PSS_SHA384_HASH_ALG, PSS_SHA384_MASK_GEN_ALG, PSS_SHA512_HASH_ALG,
    PSS_SHA512_MASK_GEN_ALG,
};
use cryptography_x509::extensions::{
    AuthorityKeyIdentifier, BasicConstraints, DuplicateExtensionsError, ExtendedKeyUsage,
    Extension, KeyUsage, SubjectAlternativeName,
};
use cryptography_x509::name::GeneralName;
use cryptography_x509::oid::{
    AUTHORITY_KEY_IDENTIFIER_OID, BASIC_CONSTRAINTS_OID, EKU_SERVER_AUTH_OID,
    EXTENDED_KEY_USAGE_OID, KEY_USAGE_OID, SUBJECT_ALTERNATIVE_NAME_OID,
    SUBJECT_DIRECTORY_ATTRIBUTES_OID, SUBJECT_KEY_IDENTIFIER_OID,
};
use once_cell::sync::Lazy;

use crate::certificate::{cert_is_self_issued, cert_is_self_signed};
use crate::ops::CryptoOps;
use crate::types::{DNSName, DNSPattern, IPAddress, IPRange};

const RFC5280_CRITICAL_CA_EXTENSIONS: &[asn1::ObjectIdentifier] =
    &[BASIC_CONSTRAINTS_OID, KEY_USAGE_OID];
const RFC5280_CRITICAL_EE_EXTENSIONS: &[asn1::ObjectIdentifier] =
    &[BASIC_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID];

static WEBPKI_PERMITTED_ALGORITHMS: Lazy<HashSet<AlgorithmIdentifier<'_>>> = Lazy::new(|| {
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
                _trailer_field: Default::default(),
            }))),
        },
        // RSASSA‐PSS with SHA‐384, MGF‐1 with SHA‐384, and a salt length of 48 bytes
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
                hash_algorithm: PSS_SHA384_HASH_ALG,
                mask_gen_algorithm: PSS_SHA384_MASK_GEN_ALG,
                salt_length: 48,
                _trailer_field: Default::default(),
            }))),
        },
        // RSASSA‐PSS with SHA‐512, MGF‐1 with SHA‐512, and a salt length of 64 bytes
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaPss(Some(Box::new(RsaPssParameters {
                hash_algorithm: PSS_SHA512_HASH_ALG,
                mask_gen_algorithm: PSS_SHA512_MASK_GEN_ALG,
                salt_length: 64,
                _trailer_field: Default::default(),
            }))),
        },
        // For P-256: the signature MUST use ECDSA with SHA‐256
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::EcDsaWithSha256(Some(())),
        },
        // For P-384: the signature MUST use ECDSA with SHA‐384
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::EcDsaWithSha384(Some(())),
        },
        // For P-521: the signature MUST use ECDSA with SHA‐512
        AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::EcDsaWithSha512(Some(())),
        },
    ])
});

#[derive(Debug, PartialEq)]
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
    fn general_name_matches(&self, general_name: &GeneralName) -> bool {
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
    pub fn matches(&self, san: SubjectAlternativeName) -> bool {
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
    ops: B,

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
            ops,
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
            ops,
            max_chain_depth: 8,
            subject,
            validation_time: time,
            extended_key_usage: EKU_SERVER_AUTH_OID.clone(),
            permitted_algorithms: Some(WEBPKI_PERMITTED_ALGORITHMS.clone()),
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

    fn permits_basic(&self, cert: &Certificate) -> Result<(), PolicyError> {
        let extensions = cert.extensions()?;

        // 5280 4.1.1.1: tbsCertificate
        // No checks required.

        // 5280 4.1.1.2 / 4.1.2.3: signatureAlgorithm / TBS Certificate Signature
        // The top-level signatureAlgorithm and TBSCert signature algorithm
        // MUST match.
        if cert.signature_alg != cert.tbs_cert.signature_alg {
            return Err("mismatch between signatureAlgorithm and SPKI algorithm".into());
        }

        // 5280 4.1.1.3: signatureValue
        // No checks required.

        // 5280 4.1.2.1: Version
        // No checks required; implementations SHOULD be prepared to accept
        // any version certificate.

        // 5280 4.1.2.2: Serial Number
        // Conforming CAs MUST NOT use serial numbers longer than 20 octets.
        // NOTE: In practice, this requires us to check for an encoding of
        // 21 octets, since some CAs generate 20 bytes of randomness and
        // then forget to check whether that number would be negative, resulting
        // in a 21-byte encoding.
        if !(1..=21).contains(&cert.tbs_cert.serial.as_bytes().len()) {
            return Err("certificate must have a serial between 1 and 20 octets".into());
        }

        // 5280 4.1.2.3: Signature
        // See check under 4.1.1.2.

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

        // 5280 4.1.2.6: Subject
        // Devolved to `permits_ca` and `permits_ee`.

        // 5280 4.1.2.7: Subject Public Key Info
        // No checks required.

        // 5280 4.1.2.8: Unique Identifiers
        // These fields MUST only appear if the certificate version is 2 or 3.
        // TODO: Check this.

        // 5280 4.1.2.9: Extensions
        // This field must MUST only appear if the certificate version is 3,
        // and it MUST be non-empty if present.
        // TODO: Check this.

        // 5280 4.2.1.1: Authority Key Identifier
        // Certificates MUST have an AuthorityKeyIdentifier, it MUST contain
        // the keyIdentifier field, and it MUST NOT be critical.
        // The exception to this is self-signed certificates, which MAY
        // omit the AuthorityKeyIdentifier.
        if let Some(aki) = extensions.get_extension(&AUTHORITY_KEY_IDENTIFIER_OID) {
            if aki.critical {
                return Err("AuthorityKeyIdentifier must not be marked critical".into());
            }

            let aki: AuthorityKeyIdentifier = aki.value()?;
            if aki.key_identifier.is_none() {
                return Err("AuthorityKeyIdentifier.keyIdentifier must be present".into());
            }
        } else if !cert_is_self_signed(cert, &self.ops) {
            return Err(
                "certificates must have a AuthorityKeyIdentifier unless self-signed".into(),
            );
        }

        // 5280 4.2.1.2: Subject Key Identifier
        // Developed to `permits_ca`.

        // 5280 4.2.1.3: Key Usage
        if let Some(key_usage) = extensions.get_extension(&KEY_USAGE_OID) {
            // KeyUsage must have at least one bit asserted, if present.
            let key_usage: KeyUsage = key_usage.value()?;
            if key_usage.is_zeroed() {
                return Err("KeyUsage must have at least one usage asserted, when present".into());
            }

            // encipherOnly or decipherOnly without keyAgreement is not well defined.
            // TODO: Check on a policy basis instead?
            if !key_usage.key_agreement()
                && (key_usage.encipher_only() || key_usage.decipher_only())
            {
                return Err(
                    "KeyUsage encipherOnly and decipherOnly can only be true when keyAgreement is true"
                        .into(),
                );
            }
        }

        // 5280 4.2.1.4: Certificate Policies
        // No checks required.

        // 5280 4.2.1.5: Policy Mappings
        // No checks required.

        // 5280 4.2.1.8: Subject Directory Attributes
        // Conforming CAs MUST mark this extension as non-critical.
        if extensions
            .get_extension(&SUBJECT_DIRECTORY_ATTRIBUTES_OID)
            .map_or(false, |e| e.critical)
        {
            return Err("SubjectDirectoryAttributes must not be marked critical".into());
        }

        // Non-profile checks follow.

        if let Some(permitted_algorithms) = &self.permitted_algorithms {
            if !permitted_algorithms.contains(&cert.signature_alg) {
                // TODO: Should probably include the OID here.
                return Err("Forbidden signature algorithm".into());
            }
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
                let san: SubjectAlternativeName = san.value()?;
                match sub.matches(san) {
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
            let mut ekus: ExtendedKeyUsage = ext.value()?;

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

    /// Checks whether the given CA certificate is compatible with this policy.
    pub(crate) fn permits_ca(&self, cert: &Certificate) -> Result<(), PolicyError> {
        self.permits_basic(cert)?;

        let extensions = cert.extensions()?;

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

        // 5280 4.2.1.2:
        // CA certificates MUST have a SubjectKeyIdentifier and it MUST NOT be
        // critical.
        if let Some(ski) = extensions.get_extension(&SUBJECT_KEY_IDENTIFIER_OID) {
            if ski.critical {
                return Err(
                    "SubjectKeyIdentifier must not be marked critical in a CA Certificate".into(),
                );
            }
        } else {
            return Err("store certificates must have a SubjectKeyIdentifier extension".into());
        }

        // 5280 4.2.1.3:
        // CA certificates MUST have a KeyUsage, it SHOULD be critical,
        // and it MUST have `keyCertSign` asserted.
        if let Some(key_usage) = extensions.get_extension(&KEY_USAGE_OID) {
            // TODO: Check `key_usage.critical` on a policy basis here?

            let key_usage: KeyUsage = key_usage.value()?;

            if !key_usage.key_cert_sign() {
                return Err("KeyUsage.keyCertSign must be asserted in a CA certificate".into());
            }
        } else {
            return Err("CA certificates must have a KeyUsage extension".into());
        }

        // 5280 4.2.1.9: Basic Constraints
        // CA certificates MUST have a BasicConstraints, it MUST be critical,
        // and it MUST have `cA` asserted.
        if let Some(basic_constraints) = extensions.get_extension(&BASIC_CONSTRAINTS_OID) {
            if !basic_constraints.critical {
                return Err("BasicConstraints must be marked critical in a CA certificate".into());
            }

            let basic_constraints: BasicConstraints = basic_constraints.value()?;
            if !basic_constraints.ca {
                return Err("BasicConstraints.cA must be asserted in a CA certificate".into());
            }
        } else {
            return Err("CA certificates must have a BasicConstraints extension".into());
        }

        // 5280 4.2.1.10: Name Constraints
        // If present, NameConstraints MUST be critical.

        // 5280 4.2.1.11: Policy Constraints
        // If present, PolicyConstraints MUST be critical.

        // CA certificates must also adhere to the expected EKU.
        self.permits_eku(extensions.get_extension(&EXTENDED_KEY_USAGE_OID))?;

        // TODO: Policy-level checks for EKUs, algorthms, etc.

        // Finally, check whether every critical extension in this CA
        // certificate is accounted for.
        for ext in extensions.iter() {
            if ext.critical && !self.critical_ca_extensions.contains(&ext.extn_id) {
                return Err(PolicyError::Other(
                    "CA certificate contains unaccounted critical extension",
                ));
            }
        }

        Ok(())
    }

    /// Checks whether the given EE certificate is compatible with this policy.
    pub(crate) fn permits_ee(&self, cert: &Certificate) -> Result<(), PolicyError> {
        // An end entity cert is considered "permitted" under a policy if:
        // 1. It satisfies the basic (both EE and CA) requirements of the underlying profile;
        // 2. It satisfies the EE-specific requirements of the profile;
        // 3. It satisfies the policy's own requirements (e.g. the cert's SANs
        //    match the policy's name).
        self.permits_basic(cert)?;

        let extensions = cert.extensions()?;

        // 4.1.2.6 / 4.2.1.6: Subject / Subject Alternative Name
        // EE certificates MAY have their subject in either the subject or subjectAltName.
        // If the subject is empty, then the subjectAltName MUST be marked critical.
        if cert.subject().is_empty() {
            match extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID) {
                Some(san) => {
                    if !san.critical {
                        return Err(
                            "EE without a subject must have a critical subjectAltName".into()
                        );
                    }

                    // TODO: There must be at least one SAN, and no SAN may be empty.
                }
                None => return Err("EE without a subject must have a subjectAltName".into()),
            }
        }

        // TODO: Pedantic: When the subject is non-empty, subjectAltName SHOULD
        // be marked as non-critical.

        // 5280 4.2.1.5: Policy Mappings
        // The RFC is not clear on whether these may appear in EE certificates.

        // 5280 4.2.1.10: Name Constraints
        // NameConstraints MUST NOT appear in EE certificates.

        // 5280 4.2.1.11: Policy Constraints
        // The RFC is not clear on whether these may appear in EE certificates.

        self.permits_san(extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID))?;
        self.permits_eku(extensions.get_extension(&EXTENDED_KEY_USAGE_OID))?;

        // TODO: Policy-level checks here for KUs, algorithms, etc.

        // Finally, check whether every critical extension in this EE certificate
        // is accounted for.
        for ext in extensions.iter() {
            if ext.critical && !self.critical_ee_extensions.contains(&ext.extn_id) {
                return Err(PolicyError::Other(
                    "EE certificate contains unaccounted critical extensions",
                ));
            }
        }

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
        issuer: &Certificate,
        child: &Certificate,
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
            .ok_or(PolicyError::Other("issuer has malformed public key"))?;
        if !self.ops.is_signed_by(child, pk) {
            return Err(PolicyError::Other("signature does not match"));
        }

        // Self-issued issuers don't increase the working depth.
        // NOTE: This is technically part of the profile's semantics.
        match cert_is_self_issued(issuer) {
            true => Ok(current_depth),
            false => Ok(current_depth + 1),
        }
    }
}

#[cfg(test)]
mod tests {}
