// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::sync::Arc;

use cryptography_x509::extensions::{Extension, Extensions};
use cryptography_x509::oid::{
    AUTHORITY_INFORMATION_ACCESS_OID, AUTHORITY_KEY_IDENTIFIER_OID, BASIC_CONSTRAINTS_OID,
    EXTENDED_KEY_USAGE_OID, KEY_USAGE_OID, NAME_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID,
    SUBJECT_KEY_IDENTIFIER_OID,
};

use crate::ops::{CryptoOps, VerificationCertificate};
use crate::policy::Policy;
use crate::{ValidationError, ValidationErrorKind, ValidationResult};

#[derive(Clone)]
pub struct ExtensionPolicy<'cb, B: CryptoOps> {
    pub authority_information_access: ExtensionValidator<'cb, B>,
    pub authority_key_identifier: ExtensionValidator<'cb, B>,
    pub subject_key_identifier: ExtensionValidator<'cb, B>,
    pub key_usage: ExtensionValidator<'cb, B>,
    pub subject_alternative_name: ExtensionValidator<'cb, B>,
    pub basic_constraints: ExtensionValidator<'cb, B>,
    pub name_constraints: ExtensionValidator<'cb, B>,
    pub extended_key_usage: ExtensionValidator<'cb, B>,
}

impl<'cb, B: CryptoOps + 'cb> ExtensionPolicy<'cb, B> {
    pub fn new_permit_all() -> Self {
        const fn make_permissive_validator<'cb, B: CryptoOps + 'cb>(
            oid: asn1::ObjectIdentifier,
        ) -> ExtensionValidator<'cb, B> {
            ExtensionValidator::MaybePresent {
                oid,
                criticality: Criticality::Agnostic,
                validator: None,
            }
        }

        ExtensionPolicy {
            authority_information_access: make_permissive_validator(
                AUTHORITY_INFORMATION_ACCESS_OID,
            ),
            authority_key_identifier: make_permissive_validator(AUTHORITY_KEY_IDENTIFIER_OID),
            subject_key_identifier: make_permissive_validator(SUBJECT_KEY_IDENTIFIER_OID),
            key_usage: make_permissive_validator(KEY_USAGE_OID),
            subject_alternative_name: make_permissive_validator(SUBJECT_ALTERNATIVE_NAME_OID),
            basic_constraints: make_permissive_validator(BASIC_CONSTRAINTS_OID),
            name_constraints: make_permissive_validator(NAME_CONSTRAINTS_OID),
            extended_key_usage: make_permissive_validator(EXTENDED_KEY_USAGE_OID),
        }
    }

    pub fn new_default_webpki_ca() -> Self {
        // NOTE: Only those checks that we are fine with users disabling should
        // be part of default ExtensionPolicies, since these are user-configurable.
        // Any constraints that are mandatory should be put directly into `Policy`.

        ExtensionPolicy {
            // 5280 4.2.2.1: Authority Information Access
            authority_information_access: ExtensionValidator::maybe_present(
                AUTHORITY_INFORMATION_ACCESS_OID,
                Criticality::NonCritical,
                Some(Arc::new(common::authority_information_access)),
            ),
            // 5280 4.2.1.1: Authority Key Identifier
            authority_key_identifier: ExtensionValidator::maybe_present(
                AUTHORITY_KEY_IDENTIFIER_OID,
                Criticality::NonCritical,
                Some(Arc::new(ca::authority_key_identifier)),
            ),
            // 5280 4.2.1.2: Subject Key Identifier
            // NOTE: CABF requires SKI in CA certificates, but many older CAs lack it.
            // We choose to be permissive here.
            subject_key_identifier: ExtensionValidator::maybe_present(
                SUBJECT_KEY_IDENTIFIER_OID,
                Criticality::NonCritical,
                None,
            ),
            // 5280 4.2.1.3: Key Usage
            key_usage: ExtensionValidator::present(
                KEY_USAGE_OID,
                Criticality::Agnostic,
                Some(Arc::new(ca::key_usage)),
            ),
            subject_alternative_name: ExtensionValidator::maybe_present(
                SUBJECT_ALTERNATIVE_NAME_OID,
                Criticality::Agnostic,
                None,
            ),
            // 5280 4.2.1.9: Basic Constraints
            basic_constraints: ExtensionValidator::present(
                BASIC_CONSTRAINTS_OID,
                Criticality::Critical,
                None, // NOTE: Mandatory validation is done in `Policy::permits_ca`
            ),
            // 5280 4.2.1.10: Name Constraints
            // NOTE: MUST be critical in 5280, but CABF relaxes to MAY.
            name_constraints: ExtensionValidator::maybe_present(
                NAME_CONSTRAINTS_OID,
                Criticality::Agnostic,
                Some(Arc::new(ca::name_constraints)),
            ),
            // 5280: 4.2.1.12: Extended Key Usage
            // NOTE: CABF requires EKUs in many non-root CA certs, but validators widely
            // ignore this requirement and treat a missing EKU as "any EKU".
            // We choose to be permissive here.
            extended_key_usage: ExtensionValidator::maybe_present(
                EXTENDED_KEY_USAGE_OID,
                Criticality::NonCritical,
                Some(Arc::new(ca::extended_key_usage)),
            ),
        }
    }

    pub fn new_default_webpki_ee() -> Self {
        // NOTE: Only those checks that we are fine with users disabling should
        // be part of default ExtensionPolicies, since these are user-configurable.
        // Any constraints that are mandatory should be put directly into `Policy`.

        ExtensionPolicy {
            // 5280 4.2.2.1: Authority Information Access
            authority_information_access: ExtensionValidator::maybe_present(
                AUTHORITY_INFORMATION_ACCESS_OID,
                Criticality::NonCritical,
                Some(Arc::new(common::authority_information_access)),
            ),
            // 5280 4.2.1.1.: Authority Key Identifier
            authority_key_identifier: ExtensionValidator::present(
                AUTHORITY_KEY_IDENTIFIER_OID,
                Criticality::NonCritical,
                None,
            ),
            subject_key_identifier: ExtensionValidator::maybe_present(
                SUBJECT_KEY_IDENTIFIER_OID,
                Criticality::Agnostic,
                None,
            ),
            // 5280 4.2.1.3: Key Usage
            key_usage: ExtensionValidator::maybe_present(
                KEY_USAGE_OID,
                Criticality::Agnostic,
                Some(Arc::new(ee::key_usage)),
            ),
            // CA/B 7.1.2.7.12 Subscriber Certificate Subject Alternative Name
            // This validator only handles the criticality checks. Matching
            // SANs against the subject in the profile is handled by
            // `Policy::permits_ee`.
            subject_alternative_name: ExtensionValidator::present(
                SUBJECT_ALTERNATIVE_NAME_OID,
                Criticality::Agnostic,
                Some(Arc::new(ee::subject_alternative_name)),
            ),
            // 5280 4.2.1.9: Basic Constraints
            basic_constraints: ExtensionValidator::maybe_present(
                BASIC_CONSTRAINTS_OID,
                Criticality::Agnostic,
                Some(Arc::new(ee::basic_constraints)),
            ),
            // 5280 4.2.1.10: Name Constraints
            name_constraints: ExtensionValidator::not_present(NAME_CONSTRAINTS_OID),
            // CA/B: 7.1.2.7.10: Subscriber Certificate Extended Key Usage
            // NOTE: CABF requires EKUs in EE certs, while RFC 5280 does not.
            extended_key_usage: ExtensionValidator::maybe_present(
                EXTENDED_KEY_USAGE_OID,
                Criticality::NonCritical,
                Some(Arc::new(ee::extended_key_usage)),
            ),
        }
    }

    pub(crate) fn permits<'chain>(
        &self,
        policy: &Policy<'_, B>,
        cert: &VerificationCertificate<'chain, B>,
        extensions: &Extensions<'_>,
    ) -> ValidationResult<'chain, (), B> {
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
                    return Err(ValidationError::new(ValidationErrorKind::ExtensionError {
                        oid: ext.extn_id,
                        reason: "certificate contains unaccounted-for critical extensions",
                    }));
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
pub enum Criticality {
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

pub type PresentExtensionValidatorCallback<'cb, B> = Arc<
    dyn for<'chain> Fn(
            &Policy<'_, B>,
            &VerificationCertificate<'chain, B>,
            &Extension<'_>,
        ) -> ValidationResult<'chain, (), B>
        + Send
        + Sync
        + 'cb,
>;

pub type MaybeExtensionValidatorCallback<'cb, B> = Arc<
    dyn for<'chain> Fn(
            &Policy<'_, B>,
            &VerificationCertificate<'chain, B>,
            Option<&Extension<'_>>,
        ) -> ValidationResult<'chain, (), B>
        + Send
        + Sync
        + 'cb,
>;

/// Represents different validation states for an extension.
#[derive(Clone)]
pub enum ExtensionValidator<'cb, B: CryptoOps> {
    /// The extension MUST NOT be present.
    NotPresent { oid: asn1::ObjectIdentifier },
    /// The extension MUST be present.
    Present {
        oid: asn1::ObjectIdentifier,
        /// The extension's criticality.
        criticality: Criticality,
        /// An optional validator over the extension's inner contents, with
        /// the surrounding `Policy` as context.
        validator: Option<PresentExtensionValidatorCallback<'cb, B>>,
    },
    /// The extension MAY be present; the interior validator is
    /// always called if supplied, including if the extension is not present.
    MaybePresent {
        oid: asn1::ObjectIdentifier,
        criticality: Criticality,
        validator: Option<MaybeExtensionValidatorCallback<'cb, B>>,
    },
}

impl<'cb, B: CryptoOps> ExtensionValidator<'cb, B> {
    pub(crate) fn not_present(oid: asn1::ObjectIdentifier) -> Self {
        Self::NotPresent { oid }
    }

    pub(crate) fn present(
        oid: asn1::ObjectIdentifier,
        criticality: Criticality,
        validator: Option<PresentExtensionValidatorCallback<'cb, B>>,
    ) -> Self {
        Self::Present {
            oid,
            criticality,
            validator,
        }
    }

    pub(crate) fn maybe_present(
        oid: asn1::ObjectIdentifier,
        criticality: Criticality,
        validator: Option<MaybeExtensionValidatorCallback<'cb, B>>,
    ) -> Self {
        Self::MaybePresent {
            oid,
            criticality,
            validator,
        }
    }

    pub(crate) fn permits<'chain>(
        &self,
        policy: &Policy<'_, B>,
        cert: &VerificationCertificate<'chain, B>,
        extension: Option<&Extension<'_>>,
    ) -> ValidationResult<'chain, (), B> {
        match (self, extension) {
            // Extension MUST NOT be present and isn't; OK.
            (ExtensionValidator::NotPresent { .. }, None) => Ok(()),
            // Extension MUST NOT be present but is; NOT OK.
            (ExtensionValidator::NotPresent { .. }, Some(extn)) => {
                Err(ValidationError::new(ValidationErrorKind::ExtensionError {
                    oid: extn.extn_id.clone(),
                    reason: "Certificate contains prohibited extension",
                }))
            }
            // Extension MUST be present but is not; NOT OK.
            (ExtensionValidator::Present { oid, .. }, None) => {
                Err(ValidationError::new(ValidationErrorKind::ExtensionError {
                    oid: oid.clone(),
                    reason: "Certificate is missing required extension",
                }))
            }
            // Extension MUST be present and is; check it.
            (
                ExtensionValidator::Present {
                    criticality,
                    validator,
                    ..
                },
                Some(extn),
            ) => {
                if !criticality.permits(extn.critical) {
                    return Err(ValidationError::new(ValidationErrorKind::ExtensionError {
                        oid: extn.extn_id.clone(),
                        reason: "Certificate extension has incorrect criticality",
                    }));
                }

                // If a custom validator is supplied, apply it.
                validator.as_ref().map_or(Ok(()), |v| v(policy, cert, extn))
            }
            // Extension MAY be present.
            (
                ExtensionValidator::MaybePresent {
                    criticality,
                    validator,
                    ..
                },
                extn,
            ) => {
                match extn {
                    // If the extension is present, apply our criticality check.
                    Some(extn) if !criticality.permits(extn.critical) => {
                        Err(ValidationError::new(ValidationErrorKind::ExtensionError {
                            oid: extn.extn_id.clone(),
                            reason: "Certificate extension has incorrect criticality",
                        }))
                    }
                    // If a custom validator is supplied, apply it.
                    _ => validator.as_ref().map_or(Ok(()), |v| v(policy, cert, extn)),
                }
            }
        }
    }
}

mod ee {
    use cryptography_x509::extensions::{BasicConstraints, ExtendedKeyUsage, Extension, KeyUsage};

    use crate::ops::{CryptoOps, VerificationCertificate};
    use crate::policy::{Policy, ValidationError, ValidationErrorKind, ValidationResult};

    pub(crate) fn basic_constraints<'chain, B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &VerificationCertificate<'chain, B>,
        extn: Option<&Extension<'_>>,
    ) -> ValidationResult<'chain, (), B> {
        if let Some(extn) = extn {
            let basic_constraints: BasicConstraints = extn.value()?;

            if basic_constraints.ca {
                return Err(ValidationError::new(ValidationErrorKind::Other(
                    "basicConstraints.cA must not be asserted in an EE certificate".to_string(),
                )));
            }
        }

        Ok(())
    }

    pub(crate) fn subject_alternative_name<'chain, B: CryptoOps>(
        _: &Policy<'_, B>,
        cert: &VerificationCertificate<'chain, B>,
        extn: &Extension<'_>,
    ) -> ValidationResult<'chain, (), B> {
        match (cert.certificate().subject().is_empty(), extn.critical) {
            // If the subject is empty, the SAN MUST be critical.
            (true, false) => {
                return Err(ValidationError::new(ValidationErrorKind::Other(
                    "EE subjectAltName MUST be critical when subject is empty".to_string(),
                )));
            }
            // If the subject is non-empty, the SAN MUST NOT be critical.
            (false, true) => {
                return Err(ValidationError::new(ValidationErrorKind::Other(
                    "EE subjectAltName MUST NOT be critical when subject is nonempty".to_string(),
                )))
            }
            _ => (),
        };

        // NOTE: policy.subject is checked against SAN elsewhere (see `ExtensionPolicy::permits`)
        // since we always want to check that, even if a custom ExtensionPolicy with a lax validator is used.

        Ok(())
    }

    pub(crate) fn extended_key_usage<'chain, B: CryptoOps>(
        policy: &Policy<'_, B>,
        _cert: &VerificationCertificate<'chain, B>,
        extn: Option<&Extension<'_>>,
    ) -> ValidationResult<'chain, (), B> {
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
                Err(ValidationError::new(ValidationErrorKind::Other(
                    "required EKU not found".to_string(),
                )))
            }
        } else {
            Ok(())
        }
    }

    pub(crate) fn key_usage<'chain, B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &VerificationCertificate<'chain, B>,
        extn: Option<&Extension<'_>>,
    ) -> ValidationResult<'chain, (), B> {
        if let Some(extn) = extn {
            let key_usage: KeyUsage<'_> = extn.value()?;

            if key_usage.key_cert_sign() {
                return Err(ValidationError::new(ValidationErrorKind::Other(
                    "EE keyUsage must not assert keyCertSign".to_string(),
                )));
            }
        }

        Ok(())
    }
}

mod ca {
    use cryptography_x509::common::Asn1Read;
    use cryptography_x509::extensions::{
        AuthorityKeyIdentifier, ExtendedKeyUsage, Extension, KeyUsage, NameConstraints,
    };
    use cryptography_x509::oid::EKU_ANY_KEY_USAGE_OID;

    use crate::ops::{CryptoOps, VerificationCertificate};
    use crate::policy::{Policy, ValidationError, ValidationErrorKind, ValidationResult};

    pub(crate) fn authority_key_identifier<'chain, B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &VerificationCertificate<'chain, B>,
        extn: Option<&Extension<'_>>,
    ) -> ValidationResult<'chain, (), B> {
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
            let aki: AuthorityKeyIdentifier<'_, Asn1Read> = extn.value()?;
            // 7.1.2.11.1 Authority Key Identifier:

            // keyIdentifier MUST be present.
            // TODO: Check that keyIdentifier matches subjectKeyIdentifier.
            if aki.key_identifier.is_none() {
                return Err(ValidationError::new(ValidationErrorKind::Other(
                    "authorityKeyIdentifier must contain keyIdentifier".to_string(),
                )));
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

    pub(crate) fn key_usage<'chain, B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &VerificationCertificate<'chain, B>,
        extn: &Extension<'_>,
    ) -> ValidationResult<'chain, (), B> {
        let key_usage: KeyUsage<'_> = extn.value()?;

        if !key_usage.key_cert_sign() {
            return Err(ValidationError::new(ValidationErrorKind::Other(
                "keyUsage.keyCertSign must be asserted in a CA certificate".to_string(),
            )));
        }

        Ok(())
    }

    pub(crate) fn name_constraints<'chain, B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &VerificationCertificate<'chain, B>,
        extn: Option<&Extension<'_>>,
    ) -> ValidationResult<'chain, (), B> {
        if let Some(extn) = extn {
            let name_constraints: NameConstraints<'_, Asn1Read> = extn.value()?;

            let permitted_subtrees_empty = name_constraints
                .permitted_subtrees
                .as_ref()
                .map_or(true, |pst| pst.is_empty());
            let excluded_subtrees_empty = name_constraints
                .excluded_subtrees
                .as_ref()
                .map_or(true, |est| est.is_empty());

            if permitted_subtrees_empty && excluded_subtrees_empty {
                return Err(ValidationError::new(ValidationErrorKind::Other(
                    "nameConstraints must have non-empty permittedSubtrees or excludedSubtrees"
                        .to_string(),
                )));
            }

            // NOTE: Both RFC 5280 and CABF require each `GeneralSubtree`
            // to have `minimum=0` and `maximum=NULL`, but experimentally
            // not many validators check for this.
        }

        Ok(())
    }

    pub(crate) fn extended_key_usage<'chain, B: CryptoOps>(
        policy: &Policy<'_, B>,
        _cert: &VerificationCertificate<'chain, B>,
        extn: Option<&Extension<'_>>,
    ) -> ValidationResult<'chain, (), B> {
        if let Some(extn) = extn {
            let mut ekus: ExtendedKeyUsage<'_> = extn.value()?;

            // NOTE: CABF explicitly forbids anyEKU in and most CA certs,
            // but this is widely (universally?) ignored by other implementations.
            if ekus.any(|eku| eku == policy.extended_key_usage || eku == EKU_ANY_KEY_USAGE_OID) {
                Ok(())
            } else {
                Err(ValidationError::new(ValidationErrorKind::Other(
                    "required EKU not found".to_string(),
                )))
            }
        } else {
            Ok(())
        }
    }
}

mod common {
    use cryptography_x509::common::Asn1Read;
    use cryptography_x509::extensions::{Extension, SequenceOfAccessDescriptions};

    use crate::ops::{CryptoOps, VerificationCertificate};
    use crate::policy::{Policy, ValidationResult};

    pub(crate) fn authority_information_access<'chain, B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &VerificationCertificate<'chain, B>,
        extn: Option<&Extension<'_>>,
    ) -> ValidationResult<'chain, (), B> {
        if let Some(extn) = extn {
            // We don't currently do anything useful with these, but we
            // do check that they're well-formed.
            let _: SequenceOfAccessDescriptions<'_, Asn1Read> = extn.value()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use asn1::{ObjectIdentifier, SimpleAsn1Writable};
    use cryptography_x509::extensions::{BasicConstraints, Extension};
    use cryptography_x509::oid::BASIC_CONSTRAINTS_OID;

    use super::{Criticality, ExtensionValidator};
    use crate::certificate::tests::PublicKeyErrorOps;
    use crate::ops::tests::{cert, epoch, v1_cert_pem};
    use crate::ops::{CryptoOps, VerificationCertificate};
    use crate::policy::{Policy, PolicyDefinition, Subject, ValidationResult};
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

    fn create_encoded_extension<T: SimpleAsn1Writable>(
        oid: ObjectIdentifier,
        critical: bool,
        ext: &T,
    ) -> Vec<u8> {
        let ext_value = asn1::write_single(ext).unwrap();
        let ext = Extension {
            extn_id: oid,
            critical,
            extn_value: &ext_value,
        };
        asn1::write_single(&ext).unwrap()
    }

    fn present_extension_validator<'chain, B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &VerificationCertificate<'chain, B>,
        _ext: &Extension<'_>,
    ) -> ValidationResult<'chain, (), B> {
        Ok(())
    }

    #[test]
    fn test_extension_validator_present() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let verification_cert = VerificationCertificate::new(&cert, ());
        let ops = PublicKeyErrorOps {};
        let policy_def = PolicyDefinition::server(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
            None,
            None,
        )
        .expect("failed to create policy definition");
        let policy = Policy::new(&policy_def, ());

        // Test a policy that stipulates that a given extension MUST be present.
        let extension_validator = ExtensionValidator::present(
            BASIC_CONSTRAINTS_OID,
            Criticality::Critical,
            Some(Arc::new(present_extension_validator)),
        );

        // Check the case where the extension is present.
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(3),
        };
        let der_ext = create_encoded_extension(BASIC_CONSTRAINTS_OID, true, &bc);
        let raw_ext = asn1::parse_single(&der_ext).unwrap();
        assert!(extension_validator
            .permits(&policy, &verification_cert, Some(&raw_ext))
            .is_ok());

        // Check the case where the extension isn't present.
        assert!(extension_validator
            .permits(&policy, &verification_cert, None)
            .is_err());
    }

    fn maybe_extension_validator<'chain, B: CryptoOps>(
        _policy: &Policy<'_, B>,
        _cert: &VerificationCertificate<'chain, B>,
        _ext: Option<&Extension<'_>>,
    ) -> ValidationResult<'chain, (), B> {
        Ok(())
    }

    #[test]
    fn test_extension_validator_maybe() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let verification_cert = VerificationCertificate::new(&cert, ());
        let ops = PublicKeyErrorOps {};
        let policy_def = PolicyDefinition::server(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
            None,
            None,
        )
        .expect("failed to create policy definition");
        let policy = Policy::new(&policy_def, ());

        // Test a validator that stipulates that a given extension CAN be present.
        let extension_validator = ExtensionValidator::maybe_present(
            BASIC_CONSTRAINTS_OID,
            Criticality::Critical,
            Some(Arc::new(maybe_extension_validator)),
        );

        // Check the case where the extension is present.
        let bc = BasicConstraints {
            ca: false,
            path_length: Some(3),
        };
        let der_ext = create_encoded_extension(BASIC_CONSTRAINTS_OID, true, &bc);
        let raw_ext = asn1::parse_single(&der_ext).unwrap();
        assert!(extension_validator
            .permits(&policy, &verification_cert, Some(&raw_ext))
            .is_ok());

        // Check the case where the extension isn't present.
        assert!(extension_validator
            .permits(&policy, &verification_cert, None)
            .is_ok());
    }

    #[test]
    fn test_extension_validator_not_present() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let verification_cert = VerificationCertificate::new(&cert, ());
        let ops = PublicKeyErrorOps {};
        let policy_def = PolicyDefinition::server(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
            None,
            None,
        )
        .expect("failed to create policy definition");
        let policy = Policy::new(&policy_def, ());

        // Test a validator that stipulates that a given extension MUST NOT be present.
        let extension_validator = ExtensionValidator::not_present(BASIC_CONSTRAINTS_OID);

        // Check the case where the extension is present.
        let bc = BasicConstraints {
            ca: false,
            path_length: Some(3),
        };
        let der_ext = create_encoded_extension(BASIC_CONSTRAINTS_OID, true, &bc);
        let raw_ext = asn1::parse_single(&der_ext).unwrap();
        assert!(extension_validator
            .permits(&policy, &verification_cert, Some(&raw_ext))
            .is_err());

        // Check the case where the extension isn't present.
        assert!(extension_validator
            .permits(&policy, &verification_cert, None)
            .is_ok());
    }

    #[test]
    fn test_extension_validator_present_incorrect_criticality() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = PublicKeyErrorOps {};
        let policy_def = PolicyDefinition::server(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
            None,
            None,
        )
        .expect("failed to create policy definition");
        let policy = Policy::new(&policy_def, ());

        // Test a present policy that stipulates that a given extension MUST be critical.
        let extension_validator = ExtensionValidator::present(
            BASIC_CONSTRAINTS_OID,
            Criticality::Critical,
            Some(Arc::new(present_extension_validator)),
        );

        // Mark the extension as non-critical despite our policy stipulating that it must be critical.
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(3),
        };
        let der_ext = create_encoded_extension(BASIC_CONSTRAINTS_OID, false, &bc);
        let raw_ext = asn1::parse_single(&der_ext).unwrap();
        assert!(extension_validator
            .permits(
                &policy,
                &VerificationCertificate::new(&cert, ()),
                Some(&raw_ext)
            )
            .is_err());
    }

    #[test]
    fn test_extension_validator_maybe_present_incorrect_criticality() {
        // The certificate doesn't get used for this validator, so the certificate we use isn't important.
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = PublicKeyErrorOps {};
        let policy_def = PolicyDefinition::server(
            ops,
            Subject::DNS(DNSName::new("example.com").unwrap()),
            epoch(),
            None,
            None,
            None,
        )
        .expect("failed to create policy definition");
        let policy = Policy::new(&policy_def, ());

        // Test a maybe present validator that stipulates that a given extension MUST be critical.
        let extension_validator = ExtensionValidator::maybe_present(
            BASIC_CONSTRAINTS_OID,
            Criticality::Critical,
            Some(Arc::new(maybe_extension_validator)),
        );

        // Mark the extension as non-critical despite our policy stipulating that it must be critical.
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(3),
        };
        let der_ext = create_encoded_extension(BASIC_CONSTRAINTS_OID, false, &bc);
        let raw_ext = asn1::parse_single(&der_ext).unwrap();
        assert!(extension_validator
            .permits(
                &policy,
                &VerificationCertificate::new(&cert, ()),
                Some(&raw_ext)
            )
            .is_err());
    }
}
