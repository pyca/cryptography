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

use crate::certificate::{cert_is_self_issued, cert_is_self_signed};
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

pub struct Intermediates<'a>(HashSet<Certificate<'a>>);

impl<'a> Intermediates<'a> {
    fn new<B: CryptoOps>(
        intermediates: impl IntoIterator<Item = Certificate<'a>>,
        policy: &Policy<'_, B>,
    ) -> Result<Self, ValidationError> {
        Ok(Self(
            intermediates
                .into_iter()
                .map(
                    |intermediate| match cert_is_self_signed(&intermediate, &policy.ops) {
                        true => Err(ValidationError::Other(
                            "self-signed certificate cannot be an intermediate".to_string(),
                        )),
                        false => Ok(intermediate),
                    },
                )
                .collect::<Result<_, _>>()?,
        ))
    }
}

pub type Chain<'c> = Vec<Certificate<'c>>;
type PartialChainState<'c> = (Chain<'c>, Vec<NameConstraints<'c>>);

pub fn verify<'a, 'chain, B: CryptoOps>(
    leaf: &'a Certificate<'chain>,
    intermediates: impl IntoIterator<Item = Certificate<'chain>>,
    policy: &Policy<'_, B>,
    store: &'a Store<'chain>,
) -> Result<Chain<'chain>, ValidationError> {
    let builder = ChainBuilder::new(Intermediates::new(intermediates, policy)?, policy, store);

    builder.build_chain(leaf)
}

struct ChainBuilder<'a, 'chain, B: CryptoOps> {
    intermediates: Intermediates<'chain>,
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
        intermediates: Intermediates<'chain>,
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
            .chain(self.intermediates.0.iter())
            .filter(|&candidate| candidate.subject() == cert.issuer())
    }

    fn build_name_constraints(
        &self,
        constraints: &mut Vec<NameConstraints<'chain>>,
        extensions: &Extensions<'chain>,
    ) -> Result<(), ValidationError> {
        if let Some(nc) = extensions.get_extension(&NAME_CONSTRAINTS_OID) {
            let nc: NameConstraints<'chain> = nc.value()?;
            constraints.push(nc);
        }
        Ok(())
    }

    fn apply_name_constraint(
        &self,
        constraint: &GeneralName<'chain>,
        san: &GeneralName<'_>,
    ) -> Result<ApplyNameConstraintStatus, ValidationError> {
        match (constraint, san) {
            (GeneralName::DNSName(pattern), GeneralName::DNSName(name)) => {
                if let Some(pattern) = DNSConstraint::new(pattern.0) {
                    let name = DNSName::new(name.0).unwrap();
                    Ok(Applied(pattern.matches(&name)))
                } else {
                    Err(ValidationError::Other(
                        "malformed DNS name constraint".to_string(),
                    ))
                }
            }
            (GeneralName::IPAddress(pattern), GeneralName::IPAddress(name)) => {
                if let Some(pattern) = IPConstraint::from_bytes(pattern) {
                    let name = IPAddress::from_bytes(name).unwrap();
                    Ok(Applied(pattern.matches(&name)))
                } else {
                    Err(ValidationError::Other(
                        "malformed IP name constraint".to_string(),
                    ))
                }
            }
            _ => Ok(Skipped),
        }
    }

    fn apply_name_constraints(
        &self,
        constraints: &[NameConstraints<'chain>],
        extensions: &Extensions<'chain>,
    ) -> Result<(), ValidationError> {
        if let Some(sans) = extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID) {
            let sans: SubjectAlternativeName<'_> = sans.value()?;
            for san in sans {
                // If there are no applicable constraints, the SAN is considered valid so the default is true.
                let mut permit = true;
                for nc in constraints {
                    if let Some(permitted_subtrees) = &nc.permitted_subtrees {
                        for p in permitted_subtrees.unwrap_read().clone() {
                            let status = self.apply_name_constraint(&p.base, &san)?;
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
                }

                for nc in constraints {
                    if let Some(excluded_subtrees) = &nc.excluded_subtrees {
                        for e in excluded_subtrees.unwrap_read().clone() {
                            let status = self.apply_name_constraint(&e.base, &san)?;
                            if status.is_match() {
                                return Err(ValidationError::Other(
                                    "excluded name constraint matched SAN".into(),
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn build_chain_inner(
        &self,
        working_cert: &'a Certificate<'chain>,
        current_depth: u8,
        is_leaf: bool,
        extensions: &'a Extensions<'chain>,
    ) -> Result<PartialChainState<'chain>, ValidationError> {
        if current_depth > self.policy.max_chain_depth {
            return Err(ValidationError::Other(
                "chain construction exceeds max depth".into(),
            ));
        }

        // Look in the store's root set to see if the working cert is listed.
        // If it is, we've reached the end.
        if self.store.contains(working_cert) {
            let mut constraints = vec![];
            self.build_name_constraints(&mut constraints, extensions)?;
            return Ok((vec![working_cert.clone()], constraints));
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
                Ok(next_depth) => {
                    match self.build_chain_inner(
                        issuing_cert_candidate,
                        next_depth,
                        false,
                        &issuer_extensions,
                    ) {
                        Ok((mut chain, mut constraints)) => {
                            // Per RFC 5280: Name constraints are not applied
                            // to self-issued certificates, *unless* the
                            // certificate is the final certificate in the path.
                            //
                            // Naively we'd check `current_depth == 0` to determine
                            // if we're checking the final certificate, but this
                            // isn't sufficient: self-issued certificates don't
                            // increase the depth, so we pass in a special-purpose
                            // `is_leaf` state that's only true on the first chain
                            // building step.
                            //
                            // See: RFC 5280 4.2.1.10
                            let skip_name_constraints =
                                cert_is_self_issued(working_cert) && !is_leaf;

                            let name_constraints_pass = match skip_name_constraints {
                                true => true,
                                false => {
                                    match self.apply_name_constraints(&constraints, extensions) {
                                        Ok(()) => true,
                                        Err(e) => {
                                            last_err = Some(e);
                                            false
                                        }
                                    }
                                }
                            };

                            if name_constraints_pass {
                                chain.insert(0, working_cert.clone());
                                self.build_name_constraints(&mut constraints, extensions)?;
                                return Ok((chain, constraints));
                            }
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
        let extensions = leaf.extensions()?;

        self.policy.permits_leaf(leaf, &extensions)?;

        let result = self.build_chain_inner(leaf, 0, true, &extensions);
        match result {
            Ok((chain, _)) => Ok(chain),
            Err(error) => Err(error),
        }
    }
}
