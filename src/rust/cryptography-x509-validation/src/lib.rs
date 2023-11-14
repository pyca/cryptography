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

use crate::certificate::cert_is_self_issued;
use crate::types::{DNSConstraint, IPAddress, IPConstraint};
use crate::ApplyNameConstraintStatus::{Applied, Skipped};
use cryptography_x509::extensions::Extensions;
use cryptography_x509::{
    certificate::Certificate,
    extensions::{NameConstraints, SubjectAlternativeName},
    name::GeneralName,
    oid::{NAME_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID},
};
use ops::CryptoOps;
use policy::{Policy, PolicyError};
use trust_store::Store;
use types::DNSName;

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    Policy(PolicyError),
}

impl From<PolicyError> for ValidationError {
    fn from(value: PolicyError) -> Self {
        ValidationError::Policy(value)
    }
}

pub type Chain<'c> = Vec<Certificate<'c>>;
type IntermediateChain<'c> = (Chain<'c>, Vec<NameConstraints<'c>>);

pub fn verify<'a, 'chain, B: CryptoOps>(
    leaf: &'a Certificate<'chain>,
    intermediates: impl IntoIterator<Item = Certificate<'chain>>,
    policy: &Policy<'_, B>,
    store: &'a Store<'chain>,
) -> Result<Chain<'chain>, ValidationError> {
    let builder = ChainBuilder::new(HashSet::from_iter(intermediates), policy, store);

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
        self.intermediates
            .iter()
            // NOTE: The intermediate set isn't allowed to offer a self-signed
            // certificate as a candidate, since self-signed certs can only
            // be roots.
            .filter(|&candidate| cert_is_self_issued(candidate))
            .chain(self.store.iter())
            .filter(|&candidate| candidate.subject() == cert.issuer())
    }

    fn build_name_constraints(
        &self,
        constraints: &mut Vec<NameConstraints<'chain>>,
        working_cert: &'a Certificate<'chain>,
    ) -> Result<(), ValidationError> {
        let extensions: Extensions<'chain> = working_cert
            .extensions()
            .map_err(|e| ValidationError::Policy(PolicyError::DuplicateExtension(e)))?;
        if let Some(nc) = extensions.get_extension(&NAME_CONSTRAINTS_OID) {
            let nc: NameConstraints<'chain> = nc.value().map_err(PolicyError::Malformed)?;
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
                    Err(PolicyError::Other("malformed DNS name constraint").into())
                }
            }
            (GeneralName::IPAddress(pattern), GeneralName::IPAddress(name)) => {
                if let Some(pattern) = IPConstraint::from_bytes(pattern) {
                    let name = IPAddress::from_bytes(name).unwrap();
                    Ok(Applied(pattern.matches(&name)))
                } else {
                    Err(PolicyError::Other("malformed IP name constraint").into())
                }
            }
            _ => Ok(Skipped),
        }
    }

    fn apply_name_constraints(
        &self,
        constraints: &Vec<NameConstraints<'chain>>,
        working_cert: &Certificate<'chain>,
    ) -> Result<(), ValidationError> {
        let extensions = working_cert
            .extensions()
            .map_err(|e| ValidationError::Policy(PolicyError::DuplicateExtension(e)))?;
        if let Some(sans) = extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID) {
            let sans: SubjectAlternativeName<'_> = sans.value().map_err(PolicyError::Malformed)?;
            for san in sans.clone() {
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
                }
                if !permit {
                    return Err(
                        PolicyError::Other("no permitted name constraints matched SAN").into(),
                    );
                }
                for nc in constraints {
                    if let Some(excluded_subtrees) = &nc.excluded_subtrees {
                        for e in excluded_subtrees.unwrap_read().clone() {
                            let status = self.apply_name_constraint(&e.base, &san)?;
                            if status.is_match() {
                                return Err(PolicyError::Other(
                                    "excluded name constraint matched SAN",
                                )
                                .into());
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
    ) -> Result<IntermediateChain<'chain>, ValidationError> {
        if current_depth > self.policy.max_chain_depth {
            return Err(PolicyError::Other("chain construction exceeds max depth").into());
        }

        // Look in the store's root set to see if the working cert is listed.
        // If it is, we've reached the end.
        //
        // Observe that no issuer connection or signature verification happens
        // here: inclusion in the root set implies a trust relationship,
        // even if the working certificate is an EE or intermediate CA.
        if self.store.contains(working_cert) {
            let mut constraints = vec![];
            self.build_name_constraints(&mut constraints, working_cert)?;
            return Ok((vec![working_cert.clone()], constraints));
        }

        // Otherwise, we collect a list of potential issuers for this cert,
        // and continue with the first that verifies.
        for issuing_cert_candidate in self.potential_issuers(working_cert) {
            // A candidate issuer is said to verify if it both
            // signs for the working certificate and conforms to the
            // policy.
            if let Ok(next_depth) =
                self.policy
                    .valid_issuer(issuing_cert_candidate, working_cert, current_depth)
            {
                let result = self.build_chain_inner(issuing_cert_candidate, next_depth, false);
                if let Ok(result) = result {
                    let (remaining, mut constraints) = result;
                    // Name constraints are not applied to self-issued certificates unless they're
                    // the leaf certificate in the chain.
                    //
                    // NOTE: We can't simply check the `current_depth` since self-issued
                    // certificates don't increase the working depth.
                    let skip_name_constraints = cert_is_self_issued(working_cert) && !is_leaf;
                    if skip_name_constraints
                        || self
                            .apply_name_constraints(&constraints, working_cert)
                            .is_ok()
                    {
                        let mut chain: Vec<Certificate<'chain>> = vec![working_cert.clone()];
                        chain.extend(remaining);
                        self.build_name_constraints(&mut constraints, working_cert)?;
                        return Ok((chain, constraints));
                    }
                }
            }
        }

        // We only reach this if we fail to hit our base case above, or if
        // a chain building step fails to find a next valid certificate.
        Err(PolicyError::Other("chain construction exhausted all candidates").into())
    }

    fn build_chain(&self, leaf: &'a Certificate<'chain>) -> Result<Chain<'chain>, ValidationError> {
        // Before anything else, check whether the given leaf cert
        // is well-formed according to our policy (and its underlying
        // certificate profile).
        //
        // In the case that the leaf is an EE, this includes a check
        // against the EE cert's SANs.
        self.policy.permits_leaf(leaf)?;

        let result = self.build_chain_inner(leaf, 0, true);
        match result {
            Ok(result) => {
                let (chain, _) = result;
                Ok(chain)
            }
            Err(error) => Err(error),
        }
    }
}
