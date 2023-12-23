// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::{HashMap, HashSet};

use cryptography_x509::certificate::Certificate;
use cryptography_x509::name::Name;

/// A `Store` represents the core state needed for X.509 path validation.
pub struct Store<'a> {
    certs: HashSet<Certificate<'a>>,
    by_subject: HashMap<Name<'a>, Vec<Certificate<'a>>>,
}

impl<'a> Store<'a> {
    /// Create a new `Store` from the given iterable certificate source.
    pub fn new(trusted: impl IntoIterator<Item = Certificate<'a>>) -> Self {
        let certs = HashSet::from_iter(trusted);
        let mut by_subject: HashMap<Name<'a>, Vec<Certificate<'a>>> = HashMap::new();
        for cert in certs.iter() {
            by_subject
                .entry(cert.tbs_cert.subject.clone())
                .or_default()
                .push(cert.clone());
        }
        Store { certs, by_subject }
    }

    /// Returns whether this store contains the given certificate.
    pub fn contains(&self, cert: &Certificate<'a>) -> bool {
        self.certs.contains(cert)
    }

    /// Returns an iterator over all certificates in this store.
    pub fn iter(&self) -> impl Iterator<Item = &Certificate<'a>> {
        self.certs.iter()
    }

    pub fn get_by_subject(&self, subject: &Name<'a>) -> &[Certificate<'a>] {
        self.by_subject
            .get(subject)
            .map(|v| v.as_slice())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use crate::ops::tests::{cert, v1_cert_pem};

    use super::Store;

    #[test]
    fn test_store() {
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let store = Store::new([cert.clone()]);

        assert!(store.contains(&cert));
        assert!(store.iter().collect::<Vec<_>>() == [&cert]);
    }
}
