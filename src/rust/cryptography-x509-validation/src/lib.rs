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
    extensions::{NameConstraints, SequenceOfSubtrees, SubjectAlternativeName},
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

#[derive(Default)]
pub struct AccumulatedNameConstraints<'a> {
    pub permitted: Vec<GeneralName<'a>>,
    pub excluded: Vec<GeneralName<'a>>,
}

pub type Chain<'c> = Vec<Certificate<'c>>;
type IntermediateChain<'c> = (Chain<'c>, AccumulatedNameConstraints<'c>);

pub fn verify<'leaf: 'chain, 'inter: 'chain, 'store: 'chain, 'chain, B: CryptoOps>(
    leaf: &'chain Certificate<'leaf>,
    intermediates: impl IntoIterator<Item = Certificate<'inter>>,
    policy: &Policy<'_, B>,
    store: &'chain Store<'store>,
) -> Result<Chain<'chain>, ValidationError> {
    let builder = ChainBuilder::new(HashSet::from_iter(intermediates), policy, store);

    builder.build_chain(leaf)
}

struct ChainBuilder<'a, 'inter, 'store, B: CryptoOps> {
    intermediates: HashSet<Certificate<'inter>>,
    policy: &'a Policy<'a, B>,
    store: &'a Store<'store>,
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

impl<'a, 'inter, 'store, 'leaf, 'chain, 'work, B: CryptoOps> ChainBuilder<'a, 'inter, 'store, B>
where
    'leaf: 'chain,
    'inter: 'chain,
    'store: 'chain,
    'work: 'leaf + 'inter,
    'chain: 'work,
{
    fn new(
        intermediates: HashSet<Certificate<'inter>>,
        policy: &'a Policy<'a, B>,
        store: &'a Store<'store>,
    ) -> Self {
        Self {
            intermediates,
            policy,
            store,
        }
    }

    fn potential_issuers(
        &'a self,
        cert: &'a Certificate<'work>,
    ) -> impl Iterator<Item = &'a Certificate<'work>> + '_ {
        // TODO: Optimizations:
        // * Use a backing structure that allows us to search by name
        //   rather than doing a linear scan
        // * Search by AKI and other identifiers?
        self.intermediates
            .iter()
            // NOTE: The intermediate set isn't allowed to offer a self-signed
            // certificate as a candidate, since self-signed certs can only
            // be roots.
            .filter(|&candidate| *candidate != *cert)
            .chain(self.store.iter())
            .filter(|&candidate| candidate.subject() == cert.issuer())
    }

    fn build_name_constraints_subtrees(
        &self,
        subtrees: SequenceOfSubtrees<'work>,
    ) -> impl Iterator<Item = GeneralName<'work>> {
        subtrees.unwrap_read().clone().map(|x| x.base)
    }

    fn build_name_constraints(
        &self,
        constraints: &mut AccumulatedNameConstraints<'work>,
        working_cert: &'a Certificate<'work>,
    ) -> Result<(), ValidationError> {
        let extensions: Extensions<'work> = working_cert
            .extensions()
            .map_err(|e| ValidationError::Policy(PolicyError::DuplicateExtension(e)))?;
        if let Some(nc) = extensions.get_extension(&NAME_CONSTRAINTS_OID) {
            let nc: NameConstraints<'work> = nc.value().map_err(PolicyError::Malformed)?;
            if let Some(permitted_subtrees) = nc.permitted_subtrees {
                constraints
                    .permitted
                    .extend(self.build_name_constraints_subtrees(permitted_subtrees));
            }
            if let Some(excluded_subtrees) = nc.excluded_subtrees {
                constraints
                    .excluded
                    .extend(self.build_name_constraints_subtrees(excluded_subtrees));
            }
        }
        Ok(())
    }

    fn apply_name_constraint(
        &self,
        constraint: &GeneralName<'work>,
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
        constraints: &AccumulatedNameConstraints<'work>,
        working_cert: &Certificate<'work>,
    ) -> Result<(), ValidationError> {
        let extensions = working_cert
            .extensions()
            .map_err(|e| ValidationError::Policy(PolicyError::DuplicateExtension(e)))?;
        if let Some(sans) = extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID) {
            let sans: SubjectAlternativeName<'_> = sans.value().map_err(PolicyError::Malformed)?;
            for san in sans.clone() {
                // If there are no applicable constraints, the SAN is considered valid so the default is true.
                let mut permit = true;
                for c in constraints.permitted.iter() {
                    let status = self.apply_name_constraint(c, &san)?;
                    if status.is_applied() {
                        permit = status.is_match();
                        if permit {
                            break;
                        }
                    }
                }
                if !permit {
                    return Err(
                        PolicyError::Other("no permitted name constraints matched SAN").into(),
                    );
                }
                for c in constraints.excluded.iter() {
                    let status = self.apply_name_constraint(c, &san)?;
                    if status.is_match() {
                        return Err(
                            PolicyError::Other("excluded name constraint matched SAN").into()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn build_chain_inner(
        &self,
        working_cert: &'a Certificate<'work>,
        current_depth: u8,
        is_leaf: bool,
    ) -> Result<IntermediateChain<'work>, ValidationError> {
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
            let mut constraints = AccumulatedNameConstraints::default();
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
                        let mut chain: Vec<Certificate<'work>> = vec![working_cert.clone()];
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

    fn build_chain(
        &self,
        leaf: &'chain Certificate<'leaf>,
    ) -> Result<Chain<'chain>, ValidationError> {
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
