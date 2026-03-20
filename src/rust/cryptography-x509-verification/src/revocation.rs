// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::crl::CertificateRevocationList;

use crate::{
    ops::{CryptoOps, VerificationCertificate},
    policy::Policy,
    ValidationResult,
};

pub trait CheckRevocation<B: CryptoOps> {
    fn is_revoked<'chain>(
        &self,
        cert: &VerificationCertificate<'chain, B>,
        issuer: &VerificationCertificate<'chain, B>,
        policy: &Policy<'_, B>,
    ) -> ValidationResult<'chain, bool, B>;
}

pub struct CrlRevocationChecker<'a> {
    crls: Vec<&'a CertificateRevocationList<'a>>,
}

impl<'a, B: CryptoOps> CheckRevocation<B> for CrlRevocationChecker<'a> {
    fn is_revoked<'chain>(
        &self,
        cert: &VerificationCertificate<'chain, B>,
        issuer: &VerificationCertificate<'chain, B>,
        policy: &Policy<'_, B>,
    ) -> ValidationResult<'chain, bool, B> {
        let _crls = &self.crls;
        let _cert = cert;
        let _issuer = issuer;
        let _policy = policy;

        Ok(false)
    }
}

impl<'a> CrlRevocationChecker<'a> {
    pub fn new(crls: impl IntoIterator<Item = &'a CertificateRevocationList<'a>>) -> Self {
        Self {
            crls: crls.into_iter().collect(),
        }
    }
}

pub type RevocationChecker<'a, B> = dyn CheckRevocation<B> + Send + Sync + 'a;
