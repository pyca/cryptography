// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::ObjectIdentifier;
use cryptography_x509::{
    certificate::Certificate,
    extensions::{Extension, Extensions},
};

use crate::{ops::CryptoOps, ValidationError};

use super::Policy;

// TODO: Remove `dead_code` attributes once we start using these helpers.

/// Represents different criticality states for an extension.
#[allow(dead_code)]
pub(crate) enum Criticality {
    /// The extension MUST be marked as critical.
    Critical,
    /// The extension MAY be marked as critical.
    Agnostic,
    /// The extension MUST NOT be marked as critical.
    NonCritical,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
type PresentExtensionValidatorCallback<B> =
    fn(&Policy<'_, B>, &Certificate<'_>, &Extension<'_>) -> Result<(), ValidationError>;

#[allow(dead_code)]
type MaybeExtensionValidatorCallback<B> =
    fn(&Policy<'_, B>, &Certificate<'_>, Option<&Extension<'_>>) -> Result<(), ValidationError>;

/// Represents different validation states for an extension.
#[allow(dead_code)]
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
#[allow(dead_code)]
pub(crate) struct ExtensionPolicy<B: CryptoOps> {
    pub(crate) oid: asn1::ObjectIdentifier,
    pub(crate) validator: ExtensionValidator<B>,
}

#[allow(dead_code)]
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
    ) -> Result<(), ValidationError> {
        match (&self.validator, extensions.get_extension(&self.oid)) {
            // Extension MUST NOT be present and isn't; OK.
            (ExtensionValidator::NotPresent, None) => Ok(()),
            // Extension MUST NOT be present but is; NOT OK.
            (ExtensionValidator::NotPresent, Some(_)) => Err(ValidationError::Other(
                "EE certificate contains prohibited extension",
            )),
            // Extension MUST be present but is not; NOT OK.
            (ExtensionValidator::Present { .. }, None) => Err(ValidationError::Other(
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
                    return Err(ValidationError::Other(
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
                    return Err(ValidationError::Other(
                        "EE certificate extension has incorrect criticality",
                    ));
                }

                // If a custom validator is supplied, apply it.
                validator.map_or(Ok(()), |v| v(policy, cert, extn.as_ref()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Criticality, ExtensionPolicy};
    use crate::ops::tests::{cert, v1_cert_pem, NullOps};
    use crate::ops::CryptoOps;
    use crate::policy::{Policy, Subject};
    use crate::types::DNSName;
    use crate::ValidationError;
    use asn1::{ObjectIdentifier, SimpleAsn1Writable};
    use cryptography_x509::certificate::Certificate;
    use cryptography_x509::extensions::{BasicConstraints, Extension, Extensions};
    use cryptography_x509::oid::BASIC_CONSTRAINTS_OID;

    #[test]
    fn test_criticality_variants() {
        let criticality = Criticality::Critical;
        assert!(criticality.permits(true));
        assert!(!criticality.permits(false));

        let criticality = Criticality::Agnostic;
        assert!(criticality.permits(true));
        assert!(criticality.permits(false));

        let criticality = Criticality::NonCritical;
        assert!(!criticality.permits(true));
        assert!(criticality.permits(false));
    }

    fn epoch() -> asn1::DateTime {
        asn1::DateTime::new(1970, 1, 1, 0, 0, 0).unwrap()
    }

    fn create_encoded_extensions<T: SimpleAsn1Writable>(
        oid: ObjectIdentifier,
        critical: bool,
        ext: &T,
    ) -> Vec<u8> {
        let ext_value = asn1::write_single(&ext).unwrap();
        let exts = vec![Extension {
            extn_id: oid,
            critical,
            extn_value: &ext_value,
        }];
        let der_exts = asn1::write_single(&asn1::SequenceOfWriter::new(exts)).unwrap();
        der_exts
    }

    fn create_empty_encoded_extensions() -> Vec<u8> {
        let exts: Vec<Extension<'_>> = vec![];
        let der_exts = asn1::write_single(&asn1::SequenceOfWriter::new(exts)).unwrap();
        der_exts
    }

    fn present_extension_validator<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        _ext: &Extension<'_>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    #[test]
    fn test_extension_policy_present() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = NullOps {};
        let policy = Policy::new(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
        );

        // Test a policy that stipulates that a given extension MUST be present.
        let extension_policy = ExtensionPolicy::present(
            BASIC_CONSTRAINTS_OID,
            Criticality::Critical,
            Some(present_extension_validator),
        );

        // Check the case where the extension is present.
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(3),
        };
        let der_exts = create_encoded_extensions(BASIC_CONSTRAINTS_OID, true, &bc);
        let raw_exts = asn1::parse_single(&der_exts).unwrap();
        let exts = Extensions::from_raw_extensions(Some(&raw_exts))
            .ok()
            .unwrap();
        assert!(extension_policy.permits(&policy, &cert, &exts).is_ok());

        // Check the case where the extension isn't present.
        let der_exts: Vec<u8> = create_empty_encoded_extensions();
        let raw_exts = asn1::parse_single(&der_exts).unwrap();
        let exts = Extensions::from_raw_extensions(Some(&raw_exts))
            .ok()
            .unwrap();
        assert!(extension_policy.permits(&policy, &cert, &exts).is_err());
    }

    fn maybe_extension_validator<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        _ext: Option<&Extension<'_>>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    #[test]
    fn test_extension_policy_maybe() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = NullOps {};
        let policy = Policy::new(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
        );

        // Test a policy that stipulates that a given extension CAN be present.
        let extension_policy = ExtensionPolicy::maybe_present(
            BASIC_CONSTRAINTS_OID,
            Criticality::Critical,
            Some(maybe_extension_validator),
        );

        // Check the case where the extension is present.
        let bc = BasicConstraints {
            ca: false,
            path_length: Some(3),
        };
        let der_exts = create_encoded_extensions(BASIC_CONSTRAINTS_OID, true, &bc);
        let raw_exts = asn1::parse_single(&der_exts).unwrap();
        let exts = Extensions::from_raw_extensions(Some(&raw_exts))
            .ok()
            .unwrap();
        assert!(extension_policy.permits(&policy, &cert, &exts).is_ok());

        // Check the case where the extension isn't present.
        let der_exts: Vec<u8> = create_empty_encoded_extensions();
        let raw_exts = asn1::parse_single(&der_exts).unwrap();
        let exts = Extensions::from_raw_extensions(Some(&raw_exts))
            .ok()
            .unwrap();
        assert!(extension_policy.permits(&policy, &cert, &exts).is_ok());
    }

    #[test]
    fn test_extension_policy_not_present() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = NullOps {};
        let policy = Policy::new(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
        );

        // Test a policy that stipulates that a given extension MUST NOT be present.
        let extension_policy = ExtensionPolicy::not_present(BASIC_CONSTRAINTS_OID);

        // Check the case where the extension is present.
        let bc = BasicConstraints {
            ca: false,
            path_length: Some(3),
        };
        let der_exts = create_encoded_extensions(BASIC_CONSTRAINTS_OID, true, &bc);
        let raw_exts = asn1::parse_single(&der_exts).unwrap();
        let exts = Extensions::from_raw_extensions(Some(&raw_exts))
            .ok()
            .unwrap();
        assert!(extension_policy.permits(&policy, &cert, &exts).is_err());

        // Check the case where the extension isn't present.
        let der_exts: Vec<u8> = create_empty_encoded_extensions();
        let raw_exts = asn1::parse_single(&der_exts).unwrap();
        let exts = Extensions::from_raw_extensions(Some(&raw_exts))
            .ok()
            .unwrap();
        assert!(extension_policy.permits(&policy, &cert, &exts).is_ok());
    }

    #[test]
    fn test_extension_policy_present_incorrect_criticality() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = NullOps {};
        let policy = Policy::new(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
        );

        // Test a present policy that stipulates that a given extension MUST be critical.
        let extension_policy = ExtensionPolicy::present(
            BASIC_CONSTRAINTS_OID,
            Criticality::Critical,
            Some(present_extension_validator),
        );

        // Mark the extension as non-critical despite our policy stipulating that it must be critical.
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(3),
        };
        let der_exts = create_encoded_extensions(BASIC_CONSTRAINTS_OID, false, &bc);
        let raw_exts = asn1::parse_single(&der_exts).unwrap();
        let exts = Extensions::from_raw_extensions(Some(&raw_exts))
            .ok()
            .unwrap();
        assert!(extension_policy.permits(&policy, &cert, &exts).is_err());
    }

    #[test]
    fn test_extension_policy_maybe_present_incorrect_criticality() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = NullOps {};
        let policy = Policy::new(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
        );

        // Test a maybe present policy that stipulates that a given extension MUST be critical.
        let extension_policy = ExtensionPolicy::maybe_present(
            BASIC_CONSTRAINTS_OID,
            Criticality::Critical,
            Some(maybe_extension_validator),
        );

        // Mark the extension as non-critical despite our policy stipulating that it must be critical.
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(3),
        };
        let der_exts = create_encoded_extensions(BASIC_CONSTRAINTS_OID, false, &bc);
        let raw_exts = asn1::parse_single(&der_exts).unwrap();
        let exts = Extensions::from_raw_extensions(Some(&raw_exts))
            .ok()
            .unwrap();
        assert!(extension_policy.permits(&policy, &cert, &exts).is_err());
    }
}
