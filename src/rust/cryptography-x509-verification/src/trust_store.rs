// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::{HashMap, HashSet};

use cryptography_x509::name::Name;

use crate::CryptoOps;
use crate::VerificationCertificate;

/// A `Store` represents the core state needed for X.509 path validation.
pub struct Store<'a, B: CryptoOps> {
    certs: HashSet<VerificationCertificate<'a, B>>,
    by_subject: HashMap<Name<'a>, Vec<VerificationCertificate<'a, B>>>,
}

impl<'a, B: CryptoOps> Store<'a, B> {
    /// Create a new `Store` from the given iterable certificate source.
    pub fn new(trusted: impl IntoIterator<Item = VerificationCertificate<'a, B>>) -> Self {
        let certs = HashSet::from_iter(trusted);
        let mut by_subject: HashMap<Name<'a>, Vec<VerificationCertificate<'a, B>>> = HashMap::new();
        for cert in certs.iter() {
            by_subject
                .entry(cert.certificate().tbs_cert.subject.clone())
                .or_default()
                .push(cert.clone());
        }
        Store { certs, by_subject }
    }

    /// Returns whether this store contains the given certificate.
    pub fn contains(&self, cert: &VerificationCertificate<'a, B>) -> bool {
        self.certs.contains(cert)
    }

    /// Returns an iterator over all certificates in this store.
    pub fn iter(&self) -> impl Iterator<Item = &VerificationCertificate<'a, B>> {
        self.certs.iter()
    }

    pub fn get_by_subject(&self, subject: &Name<'a>) -> &[VerificationCertificate<'a, B>] {
        self.by_subject
            .get(subject)
            .map(|v| v.as_slice())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::Store;
    use crate::certificate::tests::PublicKeyErrorOps;
    use crate::ops::tests::{cert, v1_cert_pem};
    use crate::VerificationCertificate;

    #[test]
    fn test_store() {
        let cert_pem = v1_cert_pem();
        let cert = VerificationCertificate::new(cert(&cert_pem), ());
        let store = Store::<'_, PublicKeyErrorOps>::new([cert.clone()]);

        assert!(store.contains(&cert));
        assert!(store.iter().collect::<Vec<_>>() == [&cert]);
    }
}
