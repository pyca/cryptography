// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::ObjectIdentifier;
use cryptography_x509::{
    certificate::Certificate,
    extensions::{Extension, Extensions},
};

use crate::ops::CryptoOps;

use super::{Policy, PolicyError};

/// Represents different criticality states for an extension.
pub(crate) enum Criticality {
    /// The extension MUST be marked as critical.
    Critical,
    /// The extension MAY be marked as critical.
    Agnostic,
    /// The extension MUST NOT be marked as critical.
    NonCritical,
}

impl Criticality {
    pub(crate) fn permits(&self, critical: bool) -> bool {
        match (self, critical) {
            (Criticality::Critical, true) => true,
            (Criticality::Critical, false) => false,
            (Criticality::Agnostic, _) => true,
            (Criticality::NonCritical, true) => false,
            (Criticality::NonCritical, false) => true,
        }
    }
}

type ExtensionValidatorCallback<B> =
    fn(&Policy<'_, B>, &Certificate<'_>, &Extension<'_>) -> Result<(), PolicyError>;

/// Represents different validation states for an extension.
pub(crate) enum ExtensionValidator<B: CryptoOps> {
    /// The extension MUST NOT be present.
    NotPresent,
    /// The extension MUST be present.
    Present {
        /// The extension's criticality.
        criticality: Criticality,
        /// An optional validator over the extension's inner contents, with
        /// the surrounding `Policy` as context.
        validator: Option<ExtensionValidatorCallback<B>>,
    },
    /// The extension MAY be present.
    MaybePresent {
        criticality: Criticality,
        validator: Option<ExtensionValidatorCallback<B>>,
    },
}

/// A "policy" for validating a specific X.509v3 extension, identified by
/// its OID.
pub(crate) struct ExtensionPolicy<B: CryptoOps> {
    pub(crate) oid: asn1::ObjectIdentifier,
    pub(crate) validator: ExtensionValidator<B>,
}

impl<B: CryptoOps> ExtensionPolicy<B> {
    pub(crate) fn not_present(oid: ObjectIdentifier) -> Self {
        Self {
            oid,
            validator: ExtensionValidator::NotPresent,
        }
    }

    pub(crate) fn present(
        oid: ObjectIdentifier,
        criticality: Criticality,
        validator: Option<ExtensionValidatorCallback<B>>,
    ) -> Self {
        Self {
            oid,
            validator: ExtensionValidator::Present {
                criticality,
                validator,
            },
        }
    }

    pub(crate) fn permits(
        &self,
        policy: &Policy<'_, B>,
        cert: &Certificate<'_>,
        extensions: &Extensions<'_>,
    ) -> Result<(), PolicyError> {
        match (&self.validator, extensions.get_extension(&self.oid)) {
            // Extension MUST NOT be present and isn't; OK.
            (ExtensionValidator::NotPresent, None) => Ok(()),
            // Extension MUST NOT be present but is; NOT OK.
            (ExtensionValidator::NotPresent, Some(_)) => Err(PolicyError::Other(
                "EE certificate contains prohibited extension",
            )),
            // Extension MUST be present but is not; NOT OK.
            (ExtensionValidator::Present { .. }, None) => Err(PolicyError::Other(
                "EE certificate is missing required extension",
            )),
            // Extension MUST be present and is; check it.
            (
                ExtensionValidator::Present {
                    criticality,
                    validator,
                },
                Some(extn),
            ) => {
                if !criticality.permits(extn.critical) {
                    return Err(PolicyError::Other(
                        "EE certificate extension has incorrect criticality",
                    ));
                }

                // If a custom validator is supplied, apply it.
                validator.map_or(Ok(()), |v| v(policy, cert, &extn))
            }
            // Extension MAY be present and is; check it.
            (
                ExtensionValidator::MaybePresent {
                    criticality,
                    validator,
                },
                Some(extn),
            ) => {
                if !criticality.permits(extn.critical) {
                    return Err(PolicyError::Other(
                        "EE certificate extension has incorrect criticality",
                    ));
                }

                // If a custom validator is supplied, apply it.
                validator.map_or(Ok(()), |v| v(policy, cert, &extn))
            }
            // Extension MAY be present and isn't; OK.
            (ExtensionValidator::MaybePresent { .. }, None) => Ok(()),
        }
    }
}

pub(crate) mod ee {}

pub(crate) mod ca {
    use cryptography_x509::{
        certificate::Certificate,
        extensions::{Extension, KeyUsage},
    };

    use crate::{
        ops::CryptoOps,
        policy::{Policy, PolicyError},
    };

    pub(crate) fn key_usage<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: &Extension<'_>,
    ) -> Result<(), PolicyError> {
        let key_usage: KeyUsage<'_> = extn.value()?;

        if !key_usage.key_cert_sign() {
            return Err("keyUsage.keyCertSign must be asserted in a CA certificate".into());
        }

        Ok(())
    }
}
