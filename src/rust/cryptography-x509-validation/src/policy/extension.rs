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

type PresentExtensionValidatorCallback<B> =
    fn(&Policy<'_, B>, &Certificate<'_>, &Extension<'_>) -> Result<(), PolicyError>;

type MaybeExtensionValidatorCallback<B> =
    fn(&Policy<'_, B>, &Certificate<'_>, Option<&Extension<'_>>) -> Result<(), PolicyError>;

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
        validator: Option<PresentExtensionValidatorCallback<B>>,
    },
    /// The extension MAY be present; the interior validator is
    /// always called if supplied, including if the extension is not present.
    MaybePresent {
        criticality: Criticality,
        validator: Option<MaybeExtensionValidatorCallback<B>>,
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
        validator: Option<PresentExtensionValidatorCallback<B>>,
    ) -> Self {
        Self {
            oid,
            validator: ExtensionValidator::Present {
                criticality,
                validator,
            },
        }
    }

    pub(crate) fn maybe_present(
        oid: ObjectIdentifier,
        criticality: Criticality,
        validator: Option<MaybeExtensionValidatorCallback<B>>,
    ) -> Self {
        Self {
            oid,
            validator: ExtensionValidator::MaybePresent {
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
            // Extension MAY be present.
            (
                ExtensionValidator::MaybePresent {
                    criticality,
                    validator,
                },
                extn,
            ) => {
                // If the extension is present, apply our criticality check.
                if extn
                    .as_ref()
                    .map_or(false, |extn| !criticality.permits(extn.critical))
                {
                    return Err(PolicyError::Other(
                        "EE certificate extension has incorrect criticality",
                    ));
                }

                // If a custom validator is supplied, apply it.
                validator.map_or(Ok(()), |v| v(policy, cert, extn.as_ref()))
            }
        }
    }
}

pub(crate) mod ee {
    use cryptography_x509::{
        certificate::Certificate,
        extensions::{BasicConstraints, Extension},
    };

    use crate::{
        ops::CryptoOps,
        policy::{Policy, PolicyError},
    };

    pub(crate) fn basic_constraints<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: Option<&Extension<'_>>,
    ) -> Result<(), PolicyError> {
        if let Some(extn) = extn {
            let basic_constraints: BasicConstraints = extn.value()?;

            if basic_constraints.ca {
                return Err("basicConstraints.cA must not be asserted in an EE certificate".into());
            }
        }

        Ok(())
    }

    pub(crate) fn subject_alternative_name<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        cert: &Certificate<'_>,
        extn: &Extension<'_>,
    ) -> Result<(), PolicyError> {
        match (cert.subject().is_empty(), extn.critical) {
            // If the subject is empty, the SAN MUST be critical.
            (true, false) => {
                return Err("EE subjectAltName MUST be critical when subject is empty".into());
            }
            // If the subject is non-empty, the SAN MUST NOT be critical.
            (false, true) => {
                return Err(
                    "EE subjectAltName MUST NOT be critical when subject is nonempty".into(),
                )
            }
            _ => (),
        };

        // For Subscriber Certificates, the Subject Alternative Name MUST be present and MUST contain at
        // least one dNSName or iPAddress GeneralName. See below for further requirements about the
        // permitted fields and their validation requirements

        Ok(())
    }
}

pub(crate) mod ca {
    use cryptography_x509::{
        certificate::Certificate,
        extensions::{BasicConstraints, Extension, KeyUsage},
    };

    use crate::{
        certificate::cert_is_self_signed,
        ops::CryptoOps,
        policy::{Policy, PolicyError},
    };

    pub(crate) fn authority_key_identifier<B: CryptoOps>(
        policy: &Policy<'_, B>,
        cert: &Certificate<'_>,
        extn: Option<&Extension<'_>>,
    ) -> Result<(), PolicyError> {
        // The Authority Key Identifier MUST be present, with one exception:
        // self-signed CAs may omit it.
        if extn.is_none() && !cert_is_self_signed(cert, &policy.ops) {
            return Err(
                "authorityKeyIdentifier must be present in cross-signed CA certificate".into(),
            );
        }

        Ok(())
    }

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

    pub(crate) fn basic_constraints<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: &Extension<'_>,
    ) -> Result<(), PolicyError> {
        let basic_constraints: BasicConstraints = extn.value()?;

        if !basic_constraints.ca {
            return Err("basicConstraints.cA must be asserted in a CA certificate".into());
        }

        Ok(())
    }
}

pub(crate) mod common {
    use cryptography_x509::{
        certificate::Certificate,
        extensions::{Extension, SequenceOfAccessDescriptions},
    };

    use crate::{
        ops::CryptoOps,
        policy::{Policy, PolicyError},
    };

    pub(crate) fn authority_information_access<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: Option<&Extension<'_>>,
    ) -> Result<(), PolicyError> {
        if let Some(extn) = extn {
            // We don't currently do anything useful with these, but we
            // do check that they're well-formed.
            let _: SequenceOfAccessDescriptions<'_> = extn.value()?;
        }

        Ok(())
    }
}
