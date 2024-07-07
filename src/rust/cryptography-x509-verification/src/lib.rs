// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]
#![allow(unknown_lints, clippy::result_large_err)]

pub mod certificate;
pub mod ops;
pub mod policy;
pub mod trust_store;
pub mod types;

use std::fmt::Display;
use std::vec;

use asn1::ObjectIdentifier;
use cryptography_x509::extensions::{DuplicateExtensionsError, Extensions};
use cryptography_x509::{
    extensions::{NameConstraints, SubjectAlternativeName},
    name::GeneralName,
    oid::{NAME_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID},
};
use types::{RFC822Constraint, RFC822Name};

use crate::certificate::cert_is_self_issued;
use crate::ops::{CryptoOps, VerificationCertificate};
use crate::policy::Policy;
use crate::trust_store::Store;
use crate::types::DNSName;
use crate::types::{DNSConstraint, IPAddress, IPConstraint};
use crate::ApplyNameConstraintStatus::{Applied, Skipped};

#[derive(Debug)]
pub enum ValidationError {
    CandidatesExhausted(Box<ValidationError>),
    Malformed(asn1::ParseError),
    ExtensionError {
        oid: ObjectIdentifier,
        reason: &'static str,
    },
    FatalError(&'static str),
    Other(String),
}

impl From<asn1::ParseError> for ValidationError {
    fn from(value: asn1::ParseError) -> Self {
        Self::Malformed(value)
    }
}

impl From<DuplicateExtensionsError> for ValidationError {
    fn from(value: DuplicateExtensionsError) -> Self {
        Self::ExtensionError {
            oid: value.0,
            reason: "duplicate extension",
        }
    }
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::CandidatesExhausted(inner) => {
                write!(f, "candidates exhausted: {inner}")
            }
            ValidationError::Malformed(err) => err.fmt(f),
            ValidationError::ExtensionError { oid, reason } => {
                write!(f, "invalid extension: {oid}: {reason}")
            }
            ValidationError::FatalError(err) => write!(f, "fatal error: {err}"),
            ValidationError::Other(err) => write!(f, "{err}"),
        }
    }
}

struct Budget {
    name_constraint_checks: usize,
}

impl Budget {
    // Same limit as other validators
    const DEFAULT_NAME_CONSTRAINT_CHECK_LIMIT: usize = 1 << 20;

    fn new() -> Budget {
        Budget {
            name_constraint_checks: Self::DEFAULT_NAME_CONSTRAINT_CHECK_LIMIT,
        }
    }

    fn name_constraint_check(&mut self) -> Result<(), ValidationError> {
        self.name_constraint_checks =
            self.name_constraint_checks
                .checked_sub(1)
                .ok_or(ValidationError::FatalError(
                    "Exceeded maximum name constraint check limit",
                ))?;
        Ok(())
    }
}

struct NameChain<'a, 'chain> {
    child: Option<&'a NameChain<'a, 'chain>>,
    sans: SubjectAlternativeName<'chain>,
}

impl<'a, 'chain> NameChain<'a, 'chain> {
    fn new(
        child: Option<&'a NameChain<'a, 'chain>>,
        extensions: &Extensions<'chain>,
        self_issued_intermediate: bool,
    ) -> Result<Self, ValidationError> {
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

    fn evaluate_single_constraint(
        &self,
        constraint: &GeneralName<'chain>,
        san: &GeneralName<'chain>,
        budget: &mut Budget,
    ) -> Result<ApplyNameConstraintStatus, ValidationError> {
        budget.name_constraint_check()?;

        match (constraint, san) {
            (GeneralName::DNSName(pattern), GeneralName::DNSName(name)) => {
                match (DNSConstraint::new(pattern.0), DNSName::new(name.0)) {
                    (Some(pattern), Some(name)) => Ok(Applied(pattern.matches(&name))),
                    (_, None) => Err(ValidationError::Other(format!(
                        "unsatisfiable DNS name constraint: malformed SAN {}",
                        name.0
                    ))),
                    (None, _) => Err(ValidationError::Other(format!(
                        "malformed DNS name constraint: {}",
                        pattern.0
                    ))),
                }
            }
            (GeneralName::IPAddress(pattern), GeneralName::IPAddress(name)) => {
                match (
                    IPConstraint::from_bytes(pattern),
                    IPAddress::from_bytes(name),
                ) {
                    (Some(pattern), Some(name)) => Ok(Applied(pattern.matches(&name))),
                    (_, None) => Err(ValidationError::Other(format!(
                        "unsatisfiable IP name constraint: malformed SAN {:?}",
                        name,
                    ))),
                    (None, _) => Err(ValidationError::Other(format!(
                        "malformed IP name constraints: {:?}",
                        pattern
                    ))),
                }
            }
            (GeneralName::RFC822Name(pattern), GeneralName::RFC822Name(name)) => {
                match (RFC822Constraint::new(pattern.0), RFC822Name::new(name.0)) {
                    (Some(pattern), Some(name)) => Ok(Applied(pattern.matches(&name))),
                    (_, None) => Err(ValidationError::Other(format!(
                        "unsatisfiable RFC822 name constraint: malformed SAN {:?}",
                        name.0,
                    ))),
                    (None, _) => Err(ValidationError::Other(format!(
                        "malformed RFC822 name constraints: {:?}",
                        pattern.0
                    ))),
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
            | (GeneralName::RegisteredID(_), GeneralName::RegisteredID(_)) => Err(
                ValidationError::Other("unsupported name constraint".to_string()),
            ),
            _ => Ok(Skipped),
        }
    }

    fn evaluate_constraints(
        &self,
        constraints: &NameConstraints<'chain>,
        budget: &mut Budget,
    ) -> Result<(), ValidationError> {
        if let Some(child) = self.child {
            child.evaluate_constraints(constraints, budget)?;
        }

        for san in self.sans.clone() {
            // If there are no applicable constraints, the SAN is considered valid so the default is true.
            let mut permit = true;
            if let Some(permitted_subtrees) = &constraints.permitted_subtrees {
                for p in permitted_subtrees.unwrap_read().clone() {
                    let status = self.evaluate_single_constraint(&p.base, &san, budget)?;
                    if status.is_applied() {
                        permit = status.is_match();
                        if permit {
                            break;
                        }
                    }
                }
            }

            if !permit {
                return Err(ValidationError::Other(
                    "no permitted name constraints matched SAN".into(),
                ));
            }

            if let Some(excluded_subtrees) = &constraints.excluded_subtrees {
                for e in excluded_subtrees.unwrap_read().clone() {
                    let status = self.evaluate_single_constraint(&e.base, &san, budget)?;
                    if status.is_match() {
                        return Err(ValidationError::Other(
                            "excluded name constraint matched SAN".into(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

pub type Chain<'a, 'c, B> = Vec<&'a VerificationCertificate<'c, B>>;

pub fn verify<'a, 'chain: 'a, B: CryptoOps>(
    leaf: &'a VerificationCertificate<'chain, B>,
    intermediates: &'a [&'a VerificationCertificate<'chain, B>],
    policy: &'a Policy<'_, B>,
    store: &'a Store<'chain, B>,
) -> Result<Chain<'a, 'chain, B>, ValidationError> {
    let builder = ChainBuilder::new(intermediates, policy, store);

    let mut budget = Budget::new();
    builder.build_chain(leaf, &mut budget)
}

struct ChainBuilder<'a, 'chain, B: CryptoOps> {
    intermediates: &'a [&'a VerificationCertificate<'chain, B>],
    policy: &'a Policy<'a, B>,
    store: &'a Store<'chain, B>,
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

impl<'a, 'chain: 'a, B: CryptoOps> ChainBuilder<'a, 'chain, B> {
    fn new(
        intermediates: &'a [&'a VerificationCertificate<'chain, B>],
        policy: &'a Policy<'a, B>,
        store: &'a Store<'chain, B>,
    ) -> Self {
        Self {
            intermediates,
            policy,
            store,
        }
    }

    fn potential_issuers(
        &self,
        cert: &'a VerificationCertificate<'chain, B>,
    ) -> impl Iterator<Item = &'a VerificationCertificate<'chain, B>> + '_ {
        // TODO: Optimizations:
        // * Search by AKI and other identifiers?
        self.store
            .get_by_subject(&cert.certificate().tbs_cert.issuer)
            .iter()
            .chain(self.intermediates.iter().copied().filter(|&candidate| {
                candidate.certificate().subject() == cert.certificate().issuer()
            }))
    }

    fn build_chain_inner(
        &self,
        working_cert: &'a VerificationCertificate<'chain, B>,
        current_depth: u8,
        working_cert_extensions: &Extensions<'chain>,
        name_chain: NameChain<'_, 'chain>,
        budget: &mut Budget,
    ) -> Result<Chain<'a, 'chain, B>, ValidationError> {
        if let Some(nc) = working_cert_extensions.get_extension(&NAME_CONSTRAINTS_OID) {
            name_chain.evaluate_constraints(&nc.value()?, budget)?;
        }

        // Look in the store's root set to see if the working cert is listed.
        // If it is, we've reached the end.
        if self.store.contains(working_cert) {
            return Ok(vec![working_cert]);
        }

        // Check that our current depth does not exceed our policy-configured
        // max depth. We do this after the root set check, since the depth
        // only measures the intermediate chain's length, not the root or leaf.
        if current_depth > self.policy.max_chain_depth {
            return Err(ValidationError::Other(
                "chain construction exceeds max depth".into(),
            ));
        }

        // Otherwise, we collect a list of potential issuers for this cert,
        // and continue with the first that verifies.
        let mut last_err: Option<ValidationError> = None;
        for issuing_cert_candidate in self.potential_issuers(working_cert) {
            // A candidate issuer is said to verify if it both
            // signs for the working certificate and conforms to the
            // policy.
            let issuer_extensions = issuing_cert_candidate.certificate().extensions()?;
            match self.policy.valid_issuer(
                issuing_cert_candidate,
                working_cert.certificate(),
                current_depth,
                &issuer_extensions,
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
                            ValidationError::Other(
                                "current depth calculation overflowed".to_string(),
                            )
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
                            chain.push(working_cert);
                            return Ok(chain);
                        }
                        // Immediately return on fatal error.
                        Err(e @ ValidationError::FatalError(..)) => return Err(e),
                        Err(e) => last_err = Some(e),
                    };
                }
                Err(e) => last_err = Some(e),
            };
        }

        // We only reach this if we fail to hit our base case above, or if
        // a chain building step fails to find a next valid certificate.
        Err(ValidationError::CandidatesExhausted(last_err.map_or_else(
            || {
                Box::new(ValidationError::Other(
                    "all candidates exhausted with no interior errors".to_string(),
                ))
            },
            |e| match e {
                // Avoid spamming the user with nested `CandidatesExhausted` errors.
                ValidationError::CandidatesExhausted(e) => e,
                _ => Box::new(e),
            },
        )))
    }

    fn build_chain(
        &self,
        leaf: &'a VerificationCertificate<'chain, B>,
        budget: &mut Budget,
    ) -> Result<Chain<'a, 'chain, B>, ValidationError> {
        // Before anything else, check whether the given leaf cert
        // is well-formed according to our policy (and its underlying
        // certificate profile).
        //
        // The leaf must be an EE; a CA cert in the leaf position will be rejected.
        let leaf_extensions = leaf.certificate().extensions()?;

        self.policy
            .permits_ee(leaf.certificate(), &leaf_extensions)?;

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
    use cryptography_x509::oid::SUBJECT_ALTERNATIVE_NAME_OID;

    use crate::ValidationError;

    #[test]
    fn test_validationerror_display() {
        let err = ValidationError::Malformed(ParseError::new(asn1::ParseErrorKind::InvalidLength));
        assert_eq!(err.to_string(), "ASN.1 parsing error: invalid length");

        let err = ValidationError::ExtensionError {
            oid: SUBJECT_ALTERNATIVE_NAME_OID,
            reason: "duplicate extension",
        };
        assert_eq!(
            err.to_string(),
            "invalid extension: 2.5.29.17: duplicate extension"
        );

        let err = ValidationError::FatalError("oops");
        assert_eq!(err.to_string(), "fatal error: oops");
    }
}
