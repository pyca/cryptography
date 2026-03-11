// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::crl::CertificateRevocationList;

use crate::{
    ops::{CryptoOps, VerificationCertificate},
    policy::Policy,
    ValidationResult,
};

trait CheckRevocation<B: CryptoOps> {
    fn is_revoked(
        &self,
        cert: &VerificationCertificate<'_, B>,
        issuer: &VerificationCertificate<'_, B>,
        policy: &Policy<'_, B>,
    ) -> ValidationResult<'_, bool, B>;
}

pub struct CrlRevocationChecker<'a> {
    crls: Vec<&'a CertificateRevocationList<'a>>,
}

impl<'a, B: CryptoOps> CheckRevocation<B> for CrlRevocationChecker<'a> {
    fn is_revoked(
        &self,
        cert: &VerificationCertificate<'_, B>,
        issuer: &VerificationCertificate<'_, B>,
        policy: &Policy<'_, B>,
    ) -> ValidationResult<'_, bool, B> {
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

/// Wrapper for revocation checkers that dispatches `is_revoked` calls to the inner implementation.
/// This allows us to avoid trait object-based polymorphism in the verifier.
pub enum RevocationChecker<'a> {
    Crl(&'a CrlRevocationChecker<'a>),
}

impl RevocationChecker<'_> {
    /// Checks the revocation status of the leaf of the provided chain.
    pub fn is_revoked<B: CryptoOps>(
        &self,
        cert: &VerificationCertificate<'_, B>,
        issuer: &VerificationCertificate<'_, B>,
        policy: &Policy<'_, B>,
    ) -> ValidationResult<'_, bool, B> {
        match self {
            RevocationChecker::Crl(c) => c.is_revoked(cert, issuer, policy),
        }
    }
}
