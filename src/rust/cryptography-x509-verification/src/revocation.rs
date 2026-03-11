// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::crl::CertificateRevocationList;

use crate::{ops::CryptoOps, policy::Policy, Chain, ValidationResult};

pub trait RevocationChecker<B: CryptoOps>: Send + Sync + RevocationCheckerClone<B> {
    fn is_revoked(
        &self,
        chain: &Chain<'_, B>,
        policy: &Policy<'_, B>,
    ) -> ValidationResult<'_, bool, B>;
}

// Instance of the trick from:
//
// https://github.com/dtolnay/dyn-clone
//
// This is necessary because implementing Clone on a trait interferes with object safety.
pub trait RevocationCheckerClone<B> {
    fn clone_box(&self) -> Box<dyn RevocationChecker<B>>;
}

impl<T, B> RevocationCheckerClone<B> for T
where
    B: CryptoOps,
    T: 'static + RevocationChecker<B> + Clone,
{
    fn clone_box(&self) -> Box<dyn RevocationChecker<B>> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
pub struct CRLRevocationChecker<'a> {
    crls: &'a [&'a CertificateRevocationList<'a>],
}

impl<B> RevocationChecker<B> for CRLRevocationChecker<'static>
where
    B: CryptoOps + Sync + Clone,
    B::PolicyExtra: Sync,
{
    fn is_revoked(
        &self,
        chain: &Chain<'_, B>,
        policy: &Policy<'_, B>,
    ) -> ValidationResult<'_, bool, B> {
        Ok(false)
    }
}

impl<'a> CRLRevocationChecker<'a> {
    pub fn new(crls: &'a [&'a CertificateRevocationList<'a>]) -> Self {
        Self { crls }
    }
}
