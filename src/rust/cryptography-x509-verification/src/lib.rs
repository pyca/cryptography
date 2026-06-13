// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]
#![allow(unknown_lints, clippy::result_large_err)]

pub mod certificate;
pub mod ops;
pub mod policy;
pub mod revocation;
pub mod trust_store;
pub mod types;

use std::fmt::Display;
use std::vec;

use asn1::ObjectIdentifier;
use cryptography_x509::common::Asn1Read;
use cryptography_x509::extensions::{
    AuthorityKeyIdentifier, DuplicateExtensionsError, Extensions, NameConstraints,
    SequenceOfSubtrees, SubjectAlternativeName,
};
use cryptography_x509::name::GeneralName;
use cryptography_x509::oid::{
    AUTHORITY_KEY_IDENTIFIER_OID, NAME_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID,
    SUBJECT_KEY_IDENTIFIER_OID,
};

use crate::certificate::cert_is_self_issued;
use crate::ops::{CryptoOps, VerificationCertificate};
use crate::policy::Policy;
use crate::revocation::CrlRevocationChecker;
use crate::trust_store::Store;
use crate::types::{
    DNSConstraint, DNSPattern, IPAddress, IPConstraint, RFC822Constraint, RFC822Name,
};
use crate::ApplyNameConstraintStatus::{Applied, Skipped};

pub enum ValidationErrorKind<'chain, B: CryptoOps> {
    CandidatesExhausted(Box<ValidationError<'chain, B>>),
    Malformed(asn1::ParseError),
    ExtensionError {
        oid: ObjectIdentifier,
        reason: &'static str,
    },
    FatalError(&'static str),
    RevocationNotDetermined(String),
    Other(String),
}

pub struct ValidationError<'chain, B: CryptoOps> {
    kind: ValidationErrorKind<'chain, B>,
    cert: Option<VerificationCertificate<'chain, B>>,
}

impl<'chain, B: CryptoOps> ValidationError<'chain, B> {
    pub fn new(kind: ValidationErrorKind<'chain, B>) -> Self {
        ValidationError { kind, cert: None }
    }

    pub(crate) fn set_cert(mut self, cert: VerificationCertificate<'chain, B>) -> Self {
        self.cert = Some(cert);
        self
    }

    pub fn certificate(&self) -> Option<&VerificationCertificate<'chain, B>> {
        self.cert.as_ref()
    }
}

pub type ValidationResult<'chain, T, B> = Result<T, ValidationError<'chain, B>>;

impl<B: CryptoOps> From<asn1::ParseError> for ValidationError<'_, B> {
    fn from(value: asn1::ParseError) -> Self {
        Self::new(ValidationErrorKind::Malformed(value))
    }
}

impl<B: CryptoOps> From<DuplicateExtensionsError> for ValidationError<'_, B> {
    fn from(value: DuplicateExtensionsError) -> Self {
        Self::new(ValidationErrorKind::ExtensionError {
            oid: value.0,
            reason: "duplicate extension",
        })
    }
}

impl<B: CryptoOps> Display for ValidationError<'_, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ValidationErrorKind::CandidatesExhausted(inner) => {
                write!(f, "candidates exhausted: {inner}")
            }
            ValidationErrorKind::Malformed(err) => err.fmt(f),
            ValidationErrorKind::ExtensionError { oid, reason } => {
                write!(f, "invalid extension: {oid}: {reason}")
            }
            ValidationErrorKind::FatalError(err) => write!(f, "fatal error: {err}"),
            ValidationErrorKind::RevocationNotDetermined(reason) => {
                write!(f, "unable to determine revocation status: {reason}")
            }
            ValidationErrorKind::Other(err) => write!(f, "{err}"),
        }
    }
}

struct Budget {
    name_constraint_checks: usize,
    signature_checks: usize,
}

impl Budget {
    // The maximum number of name constraint checks performed when attempting
    // path construction. This is the same limit as other validators.
    const DEFAULT_NAME_CONSTRAINT_CHECK_LIMIT: usize = 1 << 20;

    // The maximum number of signature verifications performed when attempting
    // path construction. The is similar to other validators:
    // both Go and rustls-webpki pick 100.
    const DEFAULT_SIGNATURE_CHECK_LIMIT: usize = 1 << 7;

    fn new() -> Budget {
        Budget {
            name_constraint_checks: Self::DEFAULT_NAME_CONSTRAINT_CHECK_LIMIT,
            signature_checks: Self::DEFAULT_SIGNATURE_CHECK_LIMIT,
        }
    }

    fn name_constraint_check<'chain, B: CryptoOps>(&mut self) -> ValidationResult<'chain, (), B> {
        self.name_constraint_checks =
            self.name_constraint_checks.checked_sub(1).ok_or_else(|| {
                ValidationError::new(ValidationErrorKind::FatalError(
                    "Exceeded maximum name constraint check limit",
                ))
            })?;
        Ok(())
    }

    fn signature_check<'chain, B: CryptoOps>(&mut self) -> ValidationResult<'chain, (), B> {
        self.signature_checks = self.signature_checks.checked_sub(1).ok_or_else(|| {
            ValidationError::new(ValidationErrorKind::FatalError(
                "Exceeded maximum signature check limit",
            ))
        })?;
        Ok(())
    }
}

struct NameChain<'a, 'chain> {
    child: Option<&'a NameChain<'a, 'chain>>,
    sans: SubjectAlternativeName<'chain>,
}

impl<'a, 'chain> NameChain<'a, 'chain> {
    fn new<B: CryptoOps>(
        child: Option<&'a NameChain<'a, 'chain>>,
        extensions: &Extensions<'chain>,
        self_issued_intermediate: bool,
    ) -> ValidationResult<'chain, Self, B> {
        let sans = match (
            self_issued_intermediate,
            extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID),
        ) {
            (false, Some(sans)) => sans.value::<SubjectAlternativeName<'chain>>()?,
            // TODO: there really ought to be a better way to express an empty
            // `asn1::SequenceOf`.
            _ => asn1::parse_single(b"\x30\x00")?,
        };

        Ok(Self { child, sans })
    }

    fn evaluate_single_constraint<B: CryptoOps>(
        &self,
        kind: SubtreeKind,
        constraint: &GeneralName<'chain>,
        san: &GeneralName<'chain>,
        budget: &mut Budget,
    ) -> ValidationResult<'chain, ApplyNameConstraintStatus, B> {
        budget.name_constraint_check()?;

        match (constraint, san) {
            (GeneralName::DNSName(constraint), GeneralName::DNSName(name)) => {
                // NOTE: A DNS SAN can be a wildcard pattern (e.g. `*.foo.com`)
                // rather than an ordinary DNS name. A wildcard represents a
                // *set* of names, so the check depends on which subtree we're
                // evaluating: a `permittedSubtrees` constraint must contain
                // *every* name the wildcard can expand to, whereas an
                // `excludedSubtrees` constraint matches if it overlaps the
                // wildcard at all. We dispatch on `kind` accordingly.
                match (DNSConstraint::new(constraint.0), DNSPattern::new(name.0)) {
                    (Some(constraint), Some(name)) => Ok(Applied(match kind {
                        SubtreeKind::Permitted => constraint.permits(&name),
                        SubtreeKind::Excluded => constraint.excludes(&name),
                    })),
                    (_, None) => Err(ValidationError::new(ValidationErrorKind::Other(format!(
                        "unsatisfiable DNS name constraint: malformed SAN {}",
                        name.0
                    )))),
                    (None, _) => Err(ValidationError::new(ValidationErrorKind::Other(format!(
                        "malformed DNS name constraint: {}",
                        constraint.0
                    )))),
                }
            }
            (GeneralName::IPAddress(constraint), GeneralName::IPAddress(name)) => {
                match (
                    IPConstraint::from_bytes(constraint),
                    IPAddress::from_bytes(name),
                ) {
                    (Some(constraint), Some(name)) => Ok(Applied(constraint.matches(&name))),
                    (_, None) => Err(ValidationError::new(ValidationErrorKind::Other(format!(
                        "unsatisfiable IP name constraint: malformed SAN {name:?}",
                    )))),
                    (None, _) => Err(ValidationError::new(ValidationErrorKind::Other(format!(
                        "malformed IP name constraints: {constraint:?}",
                    )))),
                }
            }
            (GeneralName::RFC822Name(constraint), GeneralName::RFC822Name(name)) => {
                match (RFC822Constraint::new(constraint.0), RFC822Name::new(name.0)) {
                    (Some(constraint), Some(name)) => Ok(Applied(constraint.matches(&name))),
                    (_, None) => Err(ValidationError::new(ValidationErrorKind::Other(format!(
                        "unsatisfiable RFC822 name constraint: malformed SAN {:?}",
                        name.0,
                    )))),
                    (None, _) => Err(ValidationError::new(ValidationErrorKind::Other(format!(
                        "malformed RFC822 name constraints: {:?}",
                        constraint.0
                    )))),
                }
            }
            // All other matching pairs of (constraint, name) are currently unsupported.
            (GeneralName::OtherName(_), GeneralName::OtherName(_))
            | (GeneralName::X400Address(_), GeneralName::X400Address(_))
            | (GeneralName::DirectoryName(_), GeneralName::DirectoryName(_))
            | (GeneralName::EDIPartyName(_), GeneralName::EDIPartyName(_))
            | (
                GeneralName::UniformResourceIdentifier(_),
                GeneralName::UniformResourceIdentifier(_),
            )
            | (GeneralName::RegisteredID(_), GeneralName::RegisteredID(_)) => {
                Err(ValidationError::new(ValidationErrorKind::Other(
                    "unsupported name constraint".to_string(),
                )))
            }
            _ => Ok(Skipped),
        }
    }

    fn evaluate_constraints<B: CryptoOps>(
        &self,
        constraints: &NameConstraints<'chain, Asn1Read>,
        budget: &mut Budget,
    ) -> ValidationResult<'chain, (), B> {
        if let Some(child) = self.child {
            child.evaluate_constraints(constraints, budget)?;
        }

        for san in self.sans.clone() {
            // If there are no applicable constraints, the SAN is considered valid so the default is true.
            let mut permit = true;
            if let Some(permitted_subtrees) = &constraints.permitted_subtrees {
                for p in permitted_subtrees.clone() {
                    let status = self.evaluate_single_constraint(
                        SubtreeKind::Permitted,
                        &p.base,
                        &san,
                        budget,
                    )?;
                    if status.is_applied() {
                        permit = status.is_match();
                        if permit {
                            break;
                        }
                    }
                }
            }

            if !permit {
                return Err(ValidationError::new(ValidationErrorKind::Other(
                    "no permitted name constraints matched SAN".into(),
                )));
            }

            if let Some(excluded_subtrees) = &constraints.excluded_subtrees {
                for e in excluded_subtrees.clone() {
                    let status = self.evaluate_single_constraint(
                        SubtreeKind::Excluded,
                        &e.base,
                        &san,
                        budget,
                    )?;
                    if status.is_match() {
                        return Err(ValidationError::new(ValidationErrorKind::Other(
                            "excluded name constraint matched SAN".into(),
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

pub type Chain<'c, B> = Vec<VerificationCertificate<'c, B>>;

pub fn verify<'chain, B: CryptoOps>(
    leaf: &VerificationCertificate<'chain, B>,
    intermediates: &[VerificationCertificate<'chain, B>],
    policy: &Policy<'_, B>,
    revocation_checker: Option<&'_ CrlRevocationChecker<'_>>,
    store: &Store<'chain, B>,
) -> ValidationResult<'chain, Chain<'chain, B>, B> {
    let builder = ChainBuilder::new(intermediates, policy, revocation_checker, store);

    let mut budget = Budget::new();
    builder.build_chain(leaf, &mut budget)
}

struct ChainBuilder<'a, 'chain, B: CryptoOps> {
    intermediates: &'a [VerificationCertificate<'chain, B>],
    policy: &'a Policy<'a, B>,
    revocation_checker: Option<&'a CrlRevocationChecker<'a>>,
    store: &'a Store<'chain, B>,
}

/// Identifies which kind of name constraint subtree a SAN is being evaluated
/// against. The two subtree kinds use different matching semantics for
/// wildcard DNS SANs (containment vs. overlap); see [`DNSConstraint::permits`]
/// and [`DNSConstraint::excludes`].
#[derive(Clone, Copy)]
enum SubtreeKind {
    Permitted,
    Excluded,
}

// When applying a name constraint, we need to distinguish between a few different scenarios:
// * `Applied(true)`: The name constraint is the same type as the SAN and matches.
// * `Applied(false)`: The name constraint is the same type as the SAN and does not match.
// * `Skipped`: The name constraint is a different type to the SAN.
enum ApplyNameConstraintStatus {
    Applied(bool),
    Skipped,
}

impl ApplyNameConstraintStatus {
    fn is_applied(&self) -> bool {
        matches!(self, Applied(_))
    }

    fn is_match(&self) -> bool {
        matches!(self, Applied(true))
    }
}

impl<'a, 'chain, B: CryptoOps> ChainBuilder<'a, 'chain, B> {
    fn new(
        intermediates: &'a [VerificationCertificate<'chain, B>],
        policy: &'a Policy<'a, B>,
        revocation_checker: Option<&'a CrlRevocationChecker<'a>>,
        store: &'a Store<'chain, B>,
    ) -> Self {
        Self {
            intermediates,
            policy,
            revocation_checker,
            store,
        }
    }

    /// Identify and return potential issuers for `cert`, considering
    /// candidates from both the trusted store and untrusted intermediate set.
    /// Trusted candidates are returned before untrusted intermediate
    /// candidates, and both groups are opportunisitically ordered by
    /// "likeliness" in terms of AKI/SKI match.
    fn potential_issuers(
        &self,
        cert: &'a VerificationCertificate<'chain, B>,
        cert_extensions: &Extensions<'chain>,
    ) -> Vec<&'a VerificationCertificate<'chain, B>> {
        let mut candidates: Vec<&'a VerificationCertificate<'chain, B>> = self
            .store
            .get_by_subject(&cert.certificate().tbs_cert.issuer)
            .iter()
            .chain(self.intermediates.iter().filter(|&candidate| {
                candidate.certificate().subject() == cert.certificate().issuer()
            }))
            .collect();

        let want_kid: Option<&[u8]> = cert_extensions
            .get_extension(&AUTHORITY_KEY_IDENTIFIER_OID)
            .and_then(|ext| ext.value::<AuthorityKeyIdentifier<'_, Asn1Read>>().ok())
            .and_then(|aki| aki.key_identifier);

        // This mirrors Go's `findPotentialParents`: we have a global
        // signature budget, so we want to bucket candidates by likeliness
        // to avoid wasting budget on (potentially adversarial) name collisions.
        //
        // Observe that we use a stable sort to preserve trusted candidates
        // before untrusted candidates in each likeliness bucket. In other
        // words, we always try a likely trusted candidate over an equally
        // likely untrusted one.
        //
        // See: <https://github.com/golang/go/blob/d00c67f297e/src/crypto/x509/cert_pool.go#L136>
        candidates.sort_by_key(|candidate| {
            let have_kid: Option<&[u8]> =
                candidate.certificate().extensions().ok().and_then(|exts| {
                    exts.get_extension(&SUBJECT_KEY_IDENTIFIER_OID)
                        .and_then(|ext| ext.value::<&[u8]>().ok())
                });

            match (want_kid, have_kid) {
                // cert AKID matches candidate SKID, highest likelihood.
                (Some(want), Some(have)) if want == have => 0,
                // cert AKID and candidate SKID don't match, lowest likelihood.
                (Some(_), Some(_)) => 2,
                // cert AKID and/or candidate SKID is not present, medium likelihood.
                _ => 1u8,
            }
        });
        candidates
    }

    fn build_chain_inner(
        &self,
        working_cert: &VerificationCertificate<'chain, B>,
        current_depth: u8,
        working_cert_extensions: &Extensions<'chain>,
        name_chain: NameChain<'_, 'chain>,
        budget: &mut Budget,
    ) -> ValidationResult<'chain, Chain<'chain, B>, B> {
        if let Some(revocation_checker) = self.revocation_checker {
            if revocation_checker.is_revoked(working_cert, self.policy)? {
                return Err(ValidationError::new(ValidationErrorKind::Other(
                    "certificate revoked".to_string(),
                )));
            }
        }

        if let Some(nc) = working_cert_extensions.get_extension(&NAME_CONSTRAINTS_OID) {
            let constraints: NameConstraints<'chain, Asn1Read> = nc.value()?;

            // RFC 5280 4.2.1.10 requires directoryName constraints to be
            // applied to the subject field of subsequent certificates, not
            // just to their directoryName SANs (which the evaluation below
            // would handle), and requires applications that cannot process
            // a constraint in a critical name constraints extension to
            // reject the certificate. We don't implement directoryName
            // matching, so a critical extension containing any directoryName
            // constraint is a hard error. A non-critical extension may be
            // (partially) ignored, so its directoryName constraints fall
            // through to the per-SAN evaluation below.
            fn contains_directory_name(
                subtrees: &Option<SequenceOfSubtrees<'_, Asn1Read>>,
            ) -> bool {
                subtrees.as_ref().is_some_and(|subtrees| {
                    subtrees
                        .clone()
                        .any(|subtree| matches!(subtree.base, GeneralName::DirectoryName(_)))
                })
            }
            if nc.critical
                && (contains_directory_name(&constraints.permitted_subtrees)
                    || contains_directory_name(&constraints.excluded_subtrees))
            {
                return Err(ValidationError::new(ValidationErrorKind::FatalError(
                    "critical nameConstraints extension contains an unsupported \
                     directoryName constraint",
                )));
            }

            name_chain.evaluate_constraints(&constraints, budget)?;
        }

        // Look in the store's root set to see if the working cert is listed.
        // If it is, we've reached the end.
        if self.store.contains(working_cert) {
            return Ok(vec![working_cert.clone()]);
        }

        // Check that our current depth does not exceed our policy-configured
        // max depth. We do this after the root set check, since the depth
        // only measures the intermediate chain's length, not the root or leaf.
        if current_depth > self.policy.max_chain_depth {
            return Err(ValidationError::new(ValidationErrorKind::Other(
                "chain construction exceeds max depth".into(),
            )));
        }

        // Otherwise, we collect a list of potential issuers for this cert,
        // and continue with the first that verifies.
        let mut last_err: Option<ValidationError<'_, B>> = None;
        for issuing_cert_candidate in self.potential_issuers(working_cert, working_cert_extensions)
        {
            // A candidate issuer is said to verify if it both
            // signs for the working certificate and conforms to the
            // policy.
            let issuer_extensions = issuing_cert_candidate.certificate().extensions()?;
            match self.policy.valid_issuer(
                issuing_cert_candidate,
                working_cert,
                current_depth,
                &issuer_extensions,
                budget,
            ) {
                Ok(_) => {
                    match self.build_chain_inner(
                        issuing_cert_candidate,
                        // NOTE(ww): According to RFC 5280, we should only
                        // increase the chain depth when the certificate is **not**
                        // self-issued. In practice however, implementations widely
                        // ignore this requirement, and unconditionally increment
                        // the depth with every chain member. We choose to do the same;
                        // see `pathlen::self-issued-certs-pathlen` from x509-limbo
                        // for the testcase we intentionally fail.
                        //
                        // Implementation note for someone looking to change this in the future:
                        // care should be taken to avoid infinite recursion with self-signed
                        // certificates in the intermediate set; changing this behavior will
                        // also require a "is not self-signed" check on intermediate candidates.
                        //
                        // See https://gist.github.com/woodruffw/776153088e0df3fc2f0675c5e835f7b8
                        // for an example of this change.
                        current_depth.checked_add(1).ok_or_else(|| {
                            ValidationError::new(ValidationErrorKind::Other(
                                "current depth calculation overflowed".to_string(),
                            ))
                        })?,
                        &issuer_extensions,
                        NameChain::new(
                            Some(&name_chain),
                            &issuer_extensions,
                            // Per RFC 5280 4.2.1.10: Name constraints are not applied
                            // to subjects in self-issued certificates, *unless* the
                            // certificate is the "final" (i.e., leaf) certificate in the path.
                            // We accomplish this by only collecting the SANs when the issuing
                            // candidate (which is a non-leaf by definition) isn't self-issued.
                            cert_is_self_issued(issuing_cert_candidate.certificate()),
                        )?,
                        budget,
                    ) {
                        Ok(mut chain) => {
                            chain.push(working_cert.clone());
                            return Ok(chain);
                        }
                        // Immediately return on fatal error.
                        Err(
                            e @ ValidationError {
                                kind: ValidationErrorKind::FatalError(..),
                                cert: _,
                            },
                        ) => return Err(e),
                        Err(e) => last_err = Some(e),
                    };
                }
                Err(e) => last_err = Some(e),
            };
        }

        // We only reach this if we fail to hit our base case above, or if
        // a chain building step fails to find a next valid certificate.
        Err(ValidationError::new(
            ValidationErrorKind::CandidatesExhausted(last_err.map_or_else(
                || {
                    Box::new(ValidationError::new(ValidationErrorKind::Other(
                        "all candidates exhausted with no interior errors".to_string(),
                    )))
                },
                |e| match e {
                    // Avoid spamming the user with nested `CandidatesExhausted` errors.
                    ValidationError {
                        kind: ValidationErrorKind::CandidatesExhausted(e),
                        cert: _,
                    } => e,
                    _ => Box::new(e),
                },
            )),
        ))
    }

    fn build_chain(
        &self,
        leaf: &VerificationCertificate<'chain, B>,
        budget: &mut Budget,
    ) -> ValidationResult<'chain, Chain<'chain, B>, B> {
        // Before anything else, check whether the given leaf cert
        // is well-formed according to our policy (and its underlying
        // certificate profile).
        //
        // The leaf must be an EE; a CA cert in the leaf position will be rejected.
        let leaf_extensions = leaf.certificate().extensions()?;

        self.policy
            .permits_ee(leaf, &leaf_extensions)
            .map_err(|e| e.set_cert(leaf.clone()))?;

        let mut chain = self.build_chain_inner(
            leaf,
            0,
            &leaf_extensions,
            NameChain::new(None, &leaf_extensions, false)?,
            budget,
        )?;
        // We build the chain in reverse order, fix it now.
        chain.reverse();
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use asn1::ParseError;
    use cryptography_x509::certificate::Certificate;
    use cryptography_x509::crl::CertificateRevocationList;
    use cryptography_x509::oid::SUBJECT_ALTERNATIVE_NAME_OID;

    use crate::certificate::tests::PublicKeyErrorOps;
    use crate::ops::{CryptoOps, VerificationCertificate};
    use crate::policy::{Policy, PolicyDefinition, Subject};
    use crate::trust_store::Store;
    use crate::types::DNSName;
    use crate::{Budget, ChainBuilder, NameChain, ValidationError, ValidationErrorKind};

    #[test]
    fn test_validationerror_display() {
        let err = ValidationError::<PublicKeyErrorOps>::new(ValidationErrorKind::Malformed(
            ParseError::new(asn1::ParseErrorKind::InvalidLength),
        ));
        assert_eq!(err.to_string(), "ASN.1 parsing error: invalid length");

        let err = ValidationError::<PublicKeyErrorOps>::new(ValidationErrorKind::ExtensionError {
            oid: SUBJECT_ALTERNATIVE_NAME_OID,
            reason: "duplicate extension",
        });
        assert_eq!(
            err.to_string(),
            "invalid extension: 2.5.29.17: duplicate extension"
        );

        let err = ValidationError::<PublicKeyErrorOps>::new(
            ValidationErrorKind::RevocationNotDetermined("oops".to_owned()),
        );
        assert_eq!(
            err.to_string(),
            "unable to determine revocation status: oops"
        );

        let err =
            ValidationError::<PublicKeyErrorOps>::new(ValidationErrorKind::FatalError("oops"));
        assert_eq!(err.to_string(), "fatal error: oops");
    }

    /// A `CryptoOps` whose public key extraction and signature verification
    /// always succeed, so that `valid_issuer` can be driven to completion
    /// without real cryptographic material.
    struct NullOps;

    impl CryptoOps for NullOps {
        type Key = ();
        type Err = ();
        type CertificateExtra = ();
        type PolicyExtra = ();

        fn public_key(&self, _cert: &Certificate<'_>) -> Result<Self::Key, Self::Err> {
            Ok(())
        }

        fn verify_crl_signed_by(
            &self,
            _crl: &CertificateRevocationList<'_>,
            _key: &Self::Key,
        ) -> Result<(), Self::Err> {
            Ok(())
        }

        fn verify_signed_by(
            &self,
            _cert: &Certificate<'_>,
            _key: &Self::Key,
        ) -> Result<(), Self::Err> {
            Ok(())
        }

        fn clone_public_key(_key: &Self::Key) -> Self::Key {}

        fn clone_extra(_extra: &Self::CertificateExtra) -> Self::CertificateExtra {}
    }

    #[test]
    fn test_clone() {
        assert_eq!(NullOps::clone_public_key(&()), ());
        assert_eq!(NullOps::clone_extra(&()), ());
    }

    // A self-issued ("looping") CA certificate that is its own issuer.
    fn looping_ca_pem() -> pem::Pem {
        pem::parse(
            "-----BEGIN CERTIFICATE-----
MIIBcjCCARmgAwIBAgIBATAKBggqhkjOPQQDAjAhMR8wHQYDVQQDDBZsb29waW5n
IHNlbGYtc2lnbmVkIENBMB4XDTIzMTIzMTAwMDAwMFoXDTI0MDEzMTAwMDAwMFow
ITEfMB0GA1UEAwwWbG9vcGluZyBzZWxmLXNpZ25lZCBDQTBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABKAoXUGnHdfXJbSXjRjeW+PCVHmlo4KEki69N5pJUA0QyQMR
v9ySOMnWf3Ea7TR4g3zdguwTP7LdpSku3uR1QkmjQjBAMA8GA1UdEwEB/wQFMAMB
Af8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBR23MGdG1Ma9iR+3CxKTafD/OE0
dTAKBggqhkjOPQQDAgNHADBEAiA4RCr07KfZdM16VfGNZAQFjvC60SWIU3RRVY/L
qolIOwIgCaIgj9ipK0Q0p+45UJiq+L/ncrxsweJkFq/UYubzhX0=
-----END CERTIFICATE-----",
        )
        .unwrap()
    }

    /// Exercises our pathlen overflow error scenario.
    ///
    /// This condition is logically unreachable from Python, since
    /// we unconditionally limit signature checks to a number smaller
    /// than `u8::MAX`, meaning that we always exhaust the signature budget
    /// before potentially exhausting the pathlen budget.
    ///
    /// To test that directly, we manually lift the signature budget
    /// and start our pathlen state right at `u8::MAX`, guaranteeing
    /// an overflow on the immediate chain building step.
    #[test]
    fn test_build_chain_inner_depth_overflow() {
        let pem = looping_ca_pem();
        let ca = asn1::parse_single::<Certificate<'_>>(pem.contents()).unwrap();
        let ca_exts = ca.extensions().ok().unwrap();

        // The same self-issued CA is both the working certificate and its own
        // (only) candidate issuer, so the search recurses on itself.
        let working = VerificationCertificate::<NullOps>::new(&ca, ());
        let intermediates = [VerificationCertificate::<NullOps>::new(&ca, ())];
        let store: Store<'_, NullOps> = Store::new([]);

        let subject = Subject::DNS(DNSName::new("example.com").unwrap());
        let time = asn1::DateTime::new(2024, 1, 1, 0, 0, 0).unwrap();
        let policy_def =
            PolicyDefinition::server(NullOps, subject, time, Some(u8::MAX), None, None).unwrap();
        let policy = Policy::new(&policy_def, ());

        let builder = ChainBuilder::new(&intermediates, &policy, None, &store);
        let mut budget = Budget {
            name_constraint_checks: usize::MAX,
            signature_checks: usize::MAX,
        };

        let name_chain = NameChain::new::<NullOps>(None, &ca_exts, false)
            .ok()
            .unwrap();
        let err = builder
            .build_chain_inner(&working, u8::MAX, &ca_exts, name_chain, &mut budget)
            .unwrap_err();

        assert!(matches!(
            err.kind,
            ValidationErrorKind::Other(msg) if msg.contains("current depth calculation overflowed")
        ));
    }
}
