// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]

pub mod certificate;
pub mod ops;
pub mod policy;
pub mod trust_store;
pub mod types;

use std::collections::HashSet;
use std::vec;

use crate::certificate::cert_is_self_issued;
use crate::types::{DNSConstraint, IPAddress, IPConstraint};
use crate::ApplyNameConstraintStatus::{Applied, Skipped};
use cryptography_x509::extensions::{DuplicateExtensionsError, Extensions};
use cryptography_x509::{
    certificate::Certificate,
    extensions::{NameConstraints, SubjectAlternativeName},
    name::GeneralName,
    oid::{NAME_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID},
};
use ops::CryptoOps;
use policy::Policy;
use trust_store::Store;
use types::DNSName;

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    CandidatesExhausted(Box<ValidationError>),
    Malformed(asn1::ParseError),
    DuplicateExtension(DuplicateExtensionsError),
    Other(String),
}

impl From<asn1::ParseError> for ValidationError {
    fn from(value: asn1::ParseError) -> Self {
        Self::Malformed(value)
    }
}

impl From<DuplicateExtensionsError> for ValidationError {
    fn from(value: DuplicateExtensionsError) -> Self {
        Self::DuplicateExtension(value)
    }
}

#[derive(Default)]
struct AccumulatedNameConstraints<'a> {
    sans: Vec<GeneralName<'a>>,
    name_constraints: Vec<NameConstraints<'a>>,
}

impl<'a> AccumulatedNameConstraints<'a> {
    fn accumulate_san(&mut self, extensions: &Extensions<'a>) -> Result<(), ValidationError> {
        if let Some(sans) = extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID) {
            let sans: SubjectAlternativeName<'_> = sans.value()?;
            self.sans.extend(sans);
        }

        Ok(())
    }

    fn apply_inner(
        &self,
        constraint: &GeneralName<'a>,
        san: &GeneralName<'_>,
    ) -> Result<ApplyNameConstraintStatus, ValidationError> {
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
            _ => Ok(Skipped),
        }
    }

    /// Apply the current name constraints (including those in the specified
    /// extensions, if any) to the accumulated SAN set.
    ///
    /// On success (no constraint violations found), the new constraints
    /// are additionally added to the name constraint set for future checks.
    fn apply_and_accumulate_name_constraints(
        &mut self,
        extensions: &Extensions<'a>,
    ) -> Result<(), ValidationError> {
        let new_constraints = match extensions.get_extension(&NAME_CONSTRAINTS_OID) {
            Some(nc) => Some(nc.value::<NameConstraints<'a>>()?),
            None => None,
        };

        for san in &self.sans {
            // If there are no applicable constraints, the SAN is considered valid so the default is true.
            let mut permit = true;
            for nc in self.name_constraints.iter().chain(new_constraints.iter()) {
                if let Some(permitted_subtrees) = &nc.permitted_subtrees {
                    for p in permitted_subtrees.unwrap_read().clone() {
                        let status = self.apply_inner(&p.base, san)?;
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

                if let Some(excluded_subtrees) = &nc.excluded_subtrees {
                    for e in excluded_subtrees.unwrap_read().clone() {
                        let status = self.apply_inner(&e.base, san)?;
                        if status.is_match() {
                            return Err(ValidationError::Other(
                                "excluded name constraint matched SAN".into(),
                            ));
                        }
                    }
                }
            }
        }

        if let Some(new_constraints) = new_constraints {
            self.name_constraints.push(new_constraints);
        }

        Ok(())
    }
}

pub type Chain<'c> = Vec<Certificate<'c>>;

pub fn verify<'a, 'chain, B: CryptoOps>(
    leaf: &'a Certificate<'chain>,
    intermediates: impl IntoIterator<Item = Certificate<'chain>>,
    policy: &Policy<'_, B>,
    store: &'a Store<'chain>,
) -> Result<Chain<'chain>, ValidationError> {
    let builder = ChainBuilder::new(intermediates.into_iter().collect(), policy, store);

    builder.build_chain(leaf)
}

struct ChainBuilder<'a, 'chain, B: CryptoOps> {
    intermediates: HashSet<Certificate<'chain>>,
    policy: &'a Policy<'a, B>,
    store: &'a Store<'chain>,
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
        intermediates: HashSet<Certificate<'chain>>,
        policy: &'a Policy<'a, B>,
        store: &'a Store<'chain>,
    ) -> Self {
        Self {
            intermediates,
            policy,
            store,
        }
    }

    fn potential_issuers(
        &'a self,
        cert: &'a Certificate<'chain>,
    ) -> impl Iterator<Item = &'a Certificate<'chain>> + '_ {
        // TODO: Optimizations:
        // * Use a backing structure that allows us to search by name
        //   rather than doing a linear scan
        // * Search by AKI and other identifiers?
        self.store
            .iter()
            .chain(self.intermediates.iter())
            .filter(|&candidate| candidate.subject() == cert.issuer())
    }

    fn build_chain_inner(
        &self,
        working_cert: &'a Certificate<'chain>,
        current_depth: u8,
        working_cert_extensions: &'a Extensions<'chain>,
        accumulated_constraints: &'a mut AccumulatedNameConstraints<'chain>,
    ) -> Result<Chain<'chain>, ValidationError> {
        // Per RFC 5280: Name constraints are not applied
        // to subjects in self-issued certificates, *unless* the
        // certificate is the final (i.e., leaf) certificate in the path.
        //
        // See: RFC 5280 4.2.1.10
        let skip_name_constraints = cert_is_self_issued(working_cert) && current_depth != 0;
        if !skip_name_constraints {
            accumulated_constraints.accumulate_san(working_cert_extensions)?;
        }

        accumulated_constraints.apply_and_accumulate_name_constraints(working_cert_extensions)?;

        // Look in the store's root set to see if the working cert is listed.
        // If it is, we've reached the end.
        if self.store.contains(working_cert) {
            return Ok(vec![working_cert.clone()]);
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
            let issuer_extensions = issuing_cert_candidate.extensions()?;
            match self.policy.valid_issuer(
                issuing_cert_candidate,
                working_cert,
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
                        accumulated_constraints,
                    ) {
                        Ok(mut chain) => {
                            chain.insert(0, working_cert.clone());
                            return Ok(chain);
                        }
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

    fn build_chain(&self, leaf: &'a Certificate<'chain>) -> Result<Chain<'chain>, ValidationError> {
        // Before anything else, check whether the given leaf cert
        // is well-formed according to our policy (and its underlying
        // certificate profile).
        //
        // In the case that the leaf is an EE, this includes a check
        // against the EE cert's SANs.
        let leaf_extensions = leaf.extensions()?;

        self.policy.permits_leaf(leaf, &leaf_extensions)?;

        self.build_chain_inner(
            leaf,
            0,
            &leaf_extensions,
            &mut AccumulatedNameConstraints::default(),
        )
    }
}
