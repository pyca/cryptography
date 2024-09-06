// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::oid::{
    AUTHORITY_INFORMATION_ACCESS_OID, AUTHORITY_KEY_IDENTIFIER_OID, BASIC_CONSTRAINTS_OID,
    EXTENDED_KEY_USAGE_OID, KEY_USAGE_OID, NAME_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID,
    SUBJECT_KEY_IDENTIFIER_OID,
};
use cryptography_x509::{
    certificate::Certificate,
    extensions::{Extension, Extensions},
};

use crate::{ops::CryptoOps, policy::Policy, ValidationError};

#[derive(Clone)]
pub struct ExtensionPolicy<B: CryptoOps> {
    pub(crate) authority_information_access: ExtensionValidator<B>,
    pub(crate) authority_key_identifier: ExtensionValidator<B>,
    pub(crate) subject_key_identifier: ExtensionValidator<B>,
    pub(crate) key_usage: ExtensionValidator<B>,
    pub(crate) subject_alternative_name: ExtensionValidator<B>,
    pub(crate) basic_constraints: ExtensionValidator<B>,
    pub(crate) name_constraints: ExtensionValidator<B>,
    pub(crate) extended_key_usage: ExtensionValidator<B>,
}

impl<B: CryptoOps> ExtensionPolicy<B> {
    pub(crate) fn permits(
        &self,
        policy: &Policy<'_, B>,
        cert: &Certificate<'_>,
        extensions: &Extensions<'_>,
    ) -> Result<(), ValidationError> {
        let mut authority_information_access_seen = false;
        let mut authority_key_identifier_seen = false;
        let mut subject_key_identifier_seen = false;
        let mut key_usage_seen = false;
        let mut subject_alternative_name_seen = false;
        let mut basic_constraints_seen = false;
        let mut name_constraints_seen = false;
        let mut extended_key_usage_seen = false;

        // Iterate over each extension and run its policy.
        for ext in extensions.iter() {
            match ext.extn_id {
                AUTHORITY_INFORMATION_ACCESS_OID => {
                    authority_information_access_seen = true;
                    self.authority_information_access
                        .permits(policy, cert, Some(&ext))?;
                }
                AUTHORITY_KEY_IDENTIFIER_OID => {
                    authority_key_identifier_seen = true;
                    self.authority_key_identifier
                        .permits(policy, cert, Some(&ext))?;
                }
                SUBJECT_KEY_IDENTIFIER_OID => {
                    subject_key_identifier_seen = true;
                    self.subject_key_identifier
                        .permits(policy, cert, Some(&ext))?;
                }
                KEY_USAGE_OID => {
                    key_usage_seen = true;
                    self.key_usage.permits(policy, cert, Some(&ext))?;
                }
                SUBJECT_ALTERNATIVE_NAME_OID => {
                    subject_alternative_name_seen = true;
                    self.subject_alternative_name
                        .permits(policy, cert, Some(&ext))?;
                }
                BASIC_CONSTRAINTS_OID => {
                    basic_constraints_seen = true;
                    self.basic_constraints.permits(policy, cert, Some(&ext))?;
                }
                NAME_CONSTRAINTS_OID => {
                    name_constraints_seen = true;
                    self.name_constraints.permits(policy, cert, Some(&ext))?;
                }
                EXTENDED_KEY_USAGE_OID => {
                    extended_key_usage_seen = true;
                    self.extended_key_usage.permits(policy, cert, Some(&ext))?;
                }
                _ if ext.critical => {
                    return Err(ValidationError::ExtensionError {
                        oid: ext.extn_id,
                        reason: "certificate contains unaccounted-for critical extensions",
                    });
                }
                _ => {}
            }
        }

        // Now we check if there were any required extensions that aren't
        // present
        if !authority_information_access_seen {
            self.authority_information_access
                .permits(policy, cert, None)?;
        }
        if !authority_key_identifier_seen {
            self.authority_key_identifier.permits(policy, cert, None)?;
        }
        if !subject_key_identifier_seen {
            self.subject_key_identifier.permits(policy, cert, None)?;
        }
        if !key_usage_seen {
            self.key_usage.permits(policy, cert, None)?;
        }
        if !subject_alternative_name_seen {
            self.subject_alternative_name.permits(policy, cert, None)?;
        }
        if !basic_constraints_seen {
            self.basic_constraints.permits(policy, cert, None)?;
        }
        if !name_constraints_seen {
            self.name_constraints.permits(policy, cert, None)?;
        }
        if !extended_key_usage_seen {
            self.extended_key_usage.permits(policy, cert, None)?;
        }

        Ok(())
    }
}

/// Represents different criticality states for an extension.
#[derive(Clone)]
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
    fn(&Policy<'_, B>, &Certificate<'_>, &Extension<'_>) -> Result<(), ValidationError>;

type MaybeExtensionValidatorCallback<B> =
    fn(&Policy<'_, B>, &Certificate<'_>, Option<&Extension<'_>>) -> Result<(), ValidationError>;

/// Represents different validation states for an extension.
#[derive(Clone)]
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

impl<B: CryptoOps> ExtensionValidator<B> {
    pub(crate) fn not_present() -> Self {
        Self::NotPresent
    }

    pub(crate) fn present(
        criticality: Criticality,
        validator: Option<PresentExtensionValidatorCallback<B>>,
    ) -> Self {
        Self::Present {
            criticality,
            validator,
        }
    }

    pub(crate) fn maybe_present(
        criticality: Criticality,
        validator: Option<MaybeExtensionValidatorCallback<B>>,
    ) -> Self {
        Self::MaybePresent {
            criticality,
            validator,
        }
    }

    pub(crate) fn permits(
        &self,
        policy: &Policy<'_, B>,
        cert: &Certificate<'_>,
        extension: Option<&Extension<'_>>,
    ) -> Result<(), ValidationError> {
        match (self, extension) {
            // Extension MUST NOT be present and isn't; OK.
            (ExtensionValidator::NotPresent, None) => Ok(()),
            // Extension MUST NOT be present but is; NOT OK.
            (ExtensionValidator::NotPresent, Some(extn)) => Err(ValidationError::ExtensionError {
                oid: extn.extn_id.clone(),
                reason: "Certificate contains prohibited extension",
            }),
            // Extension MUST be present but is not; NOT OK.
            (ExtensionValidator::Present { .. }, None) => Err(ValidationError::Other(
                "Certificate is missing required extension".to_string(),
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
                    return Err(ValidationError::ExtensionError {
                        oid: extn.extn_id.clone(),
                        reason: "Certificate extension has incorrect criticality",
                    });
                }

                // If a custom validator is supplied, apply it.
                validator.map_or(Ok(()), |v| v(policy, cert, extn))
            }
            // Extension MAY be present.
            (
                ExtensionValidator::MaybePresent {
                    criticality,
                    validator,
                },
                extn,
            ) => {
                match extn {
                    // If the extension is present, apply our criticality check.
                    Some(extn) if !criticality.permits(extn.critical) => {
                        Err(ValidationError::ExtensionError {
                            oid: extn.extn_id.clone(),
                            reason: "Certificate extension has incorrect criticality",
                        })
                    }
                    // If a custom validator is supplied, apply it.
                    _ => validator.map_or(Ok(()), |v| v(policy, cert, extn)),
                }
            }
        }
    }
}

pub(crate) mod ee {
    use cryptography_x509::{
        certificate::Certificate,
        extensions::{
            BasicConstraints, ExtendedKeyUsage, Extension, KeyUsage, SubjectAlternativeName,
        },
    };

    use crate::{
        ops::CryptoOps,
        policy::{Policy, ValidationError},
    };

    pub(crate) fn basic_constraints<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: Option<&Extension<'_>>,
    ) -> Result<(), ValidationError> {
        if let Some(extn) = extn {
            let basic_constraints: BasicConstraints = extn.value()?;

            if basic_constraints.ca {
                return Err(ValidationError::Other(
                    "basicConstraints.cA must not be asserted in an EE certificate".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub(crate) fn subject_alternative_name<B: CryptoOps>(
        policy: &Policy<'_, B>,
        cert: &Certificate<'_>,
        extn: &Extension<'_>,
    ) -> Result<(), ValidationError> {
        match (cert.subject().is_empty(), extn.critical) {
            // If the subject is empty, the SAN MUST be critical.
            (true, false) => {
                return Err(ValidationError::Other(
                    "EE subjectAltName MUST be critical when subject is empty".to_string(),
                ));
            }
            // If the subject is non-empty, the SAN MUST NOT be critical.
            (false, true) => {
                return Err(ValidationError::Other(
                    "EE subjectAltName MUST NOT be critical when subject is nonempty".to_string(),
                ))
            }
            _ => (),
        };

        // NOTE: We only verify the SAN against the policy's subject if the
        // policy actually contains one. This enables both client and server
        // profiles to use this validator, **with the expectation** that
        // server profile construction requires a subject to be present.
        if let Some(sub) = policy.subject.as_ref() {
            let san: SubjectAlternativeName<'_> = extn.value()?;
            if !sub.matches(&san) {
                return Err(ValidationError::Other(
                    "leaf certificate has no matching subjectAltName".into(),
                ));
            }
        }

        Ok(())
    }

    pub(crate) fn extended_key_usage<B: CryptoOps>(
        policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: Option<&Extension<'_>>,
    ) -> Result<(), ValidationError> {
        if let Some(extn) = extn {
            let mut ekus: ExtendedKeyUsage<'_> = extn.value()?;

            // CABF requires EKUs in EE certs, but this is widely ignored
            // by implementations (which treat a missing EKU as "any EKU").
            // On the other hand, if the EKU is present, it **must** be
            // the one specified in the policy (e.g., `serverAuth`) and
            // **must not** be the explicit `anyExtendedKeyUsage` EKU.
            // See: CABF 7.1.2.7.10.
            if ekus.any(|eku| eku == policy.extended_key_usage) {
                Ok(())
            } else {
                Err(ValidationError::Other("required EKU not found".to_string()))
            }
        } else {
            Ok(())
        }
    }

    pub(crate) fn key_usage<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: Option<&Extension<'_>>,
    ) -> Result<(), ValidationError> {
        if let Some(extn) = extn {
            let key_usage: KeyUsage<'_> = extn.value()?;

            if key_usage.key_cert_sign() {
                return Err(ValidationError::Other(
                    "EE keyUsage must not assert keyCertSign".to_string(),
                ));
            }
        }

        Ok(())
    }
}

pub(crate) mod ca {
    use cryptography_x509::{
        certificate::Certificate,
        extensions::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, Extension, KeyUsage,
            NameConstraints,
        },
        oid::EKU_ANY_KEY_USAGE_OID,
    };

    use crate::{
        ops::CryptoOps,
        policy::{Policy, ValidationError},
    };

    pub(crate) fn authority_key_identifier<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: Option<&Extension<'_>>,
    ) -> Result<(), ValidationError> {
        // CABF: AKI is required on all CA certificates *except* root CA certificates,
        // where is it merely recommended. This is slightly different from RFC 5280,
        // which requires AKI on all CA certificates *except* self-signed root CA certificates.
        //
        // This discrepancy poses a challenge: from a strict CABF perspective we should
        // require the AKI unless we're on a root CA, but we lack the context to determine that
        // here. We *could* infer that we're on a root by checking whether the CA is self-signed,
        // but many root CAs still use RSA with SHA-1 (which is intentionally unsupported
        // for signature verification).
        //
        // Consequently, the best we can currently do here is check whether the AKI conforms
        // to the CABF mandated format, *if* it exists. This means that we will accept
        // some chains that are not strictly CABF compliant (e.g. ones where intermediate
        // CAs are missing AKIs), but this is a relatively minor discrepancy.
        if let Some(extn) = extn {
            let aki: AuthorityKeyIdentifier<'_> = extn.value()?;
            // 7.1.2.11.1 Authority Key Identifier:

            // keyIdentifier MUST be present.
            // TODO: Check that keyIdentifier matches subjectKeyIdentifier.
            if aki.key_identifier.is_none() {
                return Err(ValidationError::Other(
                    "authorityKeyIdentifier must contain keyIdentifier".to_string(),
                ));
            }

            // NOTE: CABF 7.1.2.1.3 says that Root CAs MUST NOT
            // have authorityCertIdentifier or authorityCertSerialNumber,
            // but these are present in practice in trust program bundles
            // due to older roots that have been grandfathered in.
            // Other validators are permissive of these being present,
            // so we don't check for them.
            // See #11461 for more information.
        }

        Ok(())
    }

    pub(crate) fn key_usage<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: &Extension<'_>,
    ) -> Result<(), ValidationError> {
        let key_usage: KeyUsage<'_> = extn.value()?;

        if !key_usage.key_cert_sign() {
            return Err(ValidationError::Other(
                "keyUsage.keyCertSign must be asserted in a CA certificate".to_string(),
            ));
        }

        Ok(())
    }

    pub(crate) fn basic_constraints<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: &Extension<'_>,
    ) -> Result<(), ValidationError> {
        let basic_constraints: BasicConstraints = extn.value()?;

        if !basic_constraints.ca {
            return Err(ValidationError::Other(
                "basicConstraints.cA must be asserted in a CA certificate".to_string(),
            ));
        }

        // NOTE: basicConstraints.pathLength is checked as part of
        // `Policy::permits_ca`, since we need the current chain building
        // depth to check it.

        Ok(())
    }

    pub(crate) fn name_constraints<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: Option<&Extension<'_>>,
    ) -> Result<(), ValidationError> {
        if let Some(extn) = extn {
            let name_constraints: NameConstraints<'_> = extn.value()?;

            let permitted_subtrees_empty = name_constraints
                .permitted_subtrees
                .as_ref()
                .map_or(true, |pst| pst.unwrap_read().is_empty());
            let excluded_subtrees_empty = name_constraints
                .excluded_subtrees
                .as_ref()
                .map_or(true, |est| est.unwrap_read().is_empty());

            if permitted_subtrees_empty && excluded_subtrees_empty {
                return Err(ValidationError::Other(
                    "nameConstraints must have non-empty permittedSubtrees or excludedSubtrees"
                        .to_string(),
                ));
            }

            // NOTE: Both RFC 5280 and CABF require each `GeneralSubtree`
            // to have `minimum=0` and `maximum=NULL`, but experimentally
            // not many validators check for this.
        }

        Ok(())
    }

    pub(crate) fn extended_key_usage<B: CryptoOps>(
        policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: Option<&Extension<'_>>,
    ) -> Result<(), ValidationError> {
        if let Some(extn) = extn {
            let mut ekus: ExtendedKeyUsage<'_> = extn.value()?;

            // NOTE: CABF explicitly forbids anyEKU in and most CA certs,
            // but this is widely (universally?) ignored by other implementations.
            if ekus.any(|eku| eku == policy.extended_key_usage || eku == EKU_ANY_KEY_USAGE_OID) {
                Ok(())
            } else {
                Err(ValidationError::Other("required EKU not found".to_string()))
            }
        } else {
            Ok(())
        }
    }
}

pub(crate) mod common {
    use cryptography_x509::{
        certificate::Certificate,
        extensions::{Extension, SequenceOfAccessDescriptions},
    };

    use crate::{
        ops::CryptoOps,
        policy::{Policy, ValidationError},
    };

    pub(crate) fn authority_information_access<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        extn: Option<&Extension<'_>>,
    ) -> Result<(), ValidationError> {
        if let Some(extn) = extn {
            // We don't currently do anything useful with these, but we
            // do check that they're well-formed.
            let _: SequenceOfAccessDescriptions<'_> = extn.value()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use asn1::{ObjectIdentifier, SimpleAsn1Writable};
    use cryptography_x509::certificate::Certificate;
    use cryptography_x509::extensions::{BasicConstraints, Extension};
    use cryptography_x509::oid::BASIC_CONSTRAINTS_OID;

    use super::{Criticality, ExtensionValidator};
    use crate::certificate::tests::PublicKeyErrorOps;
    use crate::ops::tests::{cert, v1_cert_pem};
    use crate::ops::CryptoOps;
    use crate::policy::{Policy, Subject, ValidationError};
    use crate::types::DNSName;

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

    fn create_encoded_extension<T: SimpleAsn1Writable>(
        oid: ObjectIdentifier,
        critical: bool,
        ext: &T,
    ) -> Vec<u8> {
        let ext_value = asn1::write_single(&ext).unwrap();
        let ext = Extension {
            extn_id: oid,
            critical,
            extn_value: &ext_value,
        };
        asn1::write_single(&ext).unwrap()
    }

    fn present_extension_validator<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        _ext: &Extension<'_>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    #[test]
    fn test_extension_validator_present() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = PublicKeyErrorOps {};
        let policy = Policy::server(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
        );

        // Test a policy that stipulates that a given extension MUST be present.
        let extension_validator =
            ExtensionValidator::present(Criticality::Critical, Some(present_extension_validator));

        // Check the case where the extension is present.
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(3),
        };
        let der_ext = create_encoded_extension(BASIC_CONSTRAINTS_OID, true, &bc);
        let raw_ext = asn1::parse_single(&der_ext).unwrap();
        assert!(extension_validator
            .permits(&policy, &cert, Some(&raw_ext))
            .is_ok());

        // Check the case where the extension isn't present.
        assert!(extension_validator.permits(&policy, &cert, None).is_err());
    }

    fn maybe_extension_validator<B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &Certificate<'_>,
        _ext: Option<&Extension<'_>>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    #[test]
    fn test_extension_validator_maybe() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = PublicKeyErrorOps {};
        let policy = Policy::server(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
        );

        // Test a validator that stipulates that a given extension CAN be present.
        let extension_validator = ExtensionValidator::maybe_present(
            Criticality::Critical,
            Some(maybe_extension_validator),
        );

        // Check the case where the extension is present.
        let bc = BasicConstraints {
            ca: false,
            path_length: Some(3),
        };
        let der_ext = create_encoded_extension(BASIC_CONSTRAINTS_OID, true, &bc);
        let raw_ext = asn1::parse_single(&der_ext).unwrap();
        assert!(extension_validator
            .permits(&policy, &cert, Some(&raw_ext))
            .is_ok());

        // Check the case where the extension isn't present.
        assert!(extension_validator.permits(&policy, &cert, None).is_ok());
    }

    #[test]
    fn test_extension_validator_not_present() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = PublicKeyErrorOps {};
        let policy = Policy::server(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
        );

        // Test a validator that stipulates that a given extension MUST NOT be present.
        let extension_validator = ExtensionValidator::not_present();

        // Check the case where the extension is present.
        let bc = BasicConstraints {
            ca: false,
            path_length: Some(3),
        };
        let der_ext = create_encoded_extension(BASIC_CONSTRAINTS_OID, true, &bc);
        let raw_ext = asn1::parse_single(&der_ext).unwrap();
        assert!(extension_validator
            .permits(&policy, &cert, Some(&raw_ext))
            .is_err());

        // Check the case where the extension isn't present.
        assert!(extension_validator.permits(&policy, &cert, None).is_ok());
    }

    #[test]
    fn test_extension_validator_present_incorrect_criticality() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = PublicKeyErrorOps {};
        let policy = Policy::server(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
        );

        // Test a present policy that stipulates that a given extension MUST be critical.
        let extension_validator =
            ExtensionValidator::present(Criticality::Critical, Some(present_extension_validator));

        // Mark the extension as non-critical despite our policy stipulating that it must be critical.
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(3),
        };
        let der_ext = create_encoded_extension(BASIC_CONSTRAINTS_OID, false, &bc);
        let raw_ext = asn1::parse_single(&der_ext).unwrap();
        assert!(extension_validator
            .permits(&policy, &cert, Some(&raw_ext))
            .is_err());
    }

    #[test]
    fn test_extension_validator_maybe_present_incorrect_criticality() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = PublicKeyErrorOps {};
        let policy = Policy::server(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
        );

        // Test a maybe present validator that stipulates that a given extension MUST be critical.
        let extension_validator = ExtensionValidator::maybe_present(
            Criticality::Critical,
            Some(maybe_extension_validator),
        );

        // Mark the extension as non-critical despite our policy stipulating that it must be critical.
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(3),
        };
        let der_ext = create_encoded_extension(BASIC_CONSTRAINTS_OID, false, &bc);
        let raw_ext = asn1::parse_single(&der_ext).unwrap();
        assert!(extension_validator
            .permits(&policy, &cert, Some(&raw_ext))
            .is_err());
    }
}
