// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::HashSet;

use cryptography_x509::certificate::Certificate;

/// A `Store` represents the core state needed for X.509 path validation.
pub struct Store<'a>(HashSet<Certificate<'a>>);

impl<'a> Store<'a> {
    /// Create a new `Store` from the given iterable certificate source.
    pub fn new(trusted: impl IntoIterator<Item = Certificate<'a>>) -> Self {
        Store(HashSet::from_iter(trusted))
    }

    /// Returns whether this store contains the given certificate.
    pub fn contains(&self, cert: &Certificate<'a>) -> bool {
        self.0.contains(cert)
    }

    /// Returns an iterator over all certificates in this store.
    pub fn iter(&self) -> impl Iterator<Item = &Certificate<'a>> {
        self.0.iter()
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
