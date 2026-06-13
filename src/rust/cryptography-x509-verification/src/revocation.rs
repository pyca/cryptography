// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::{HashMap, HashSet};

use cryptography_x509::{
    certificate::Certificate,
    common::Asn1Read,
    crl::{CertificateRevocationList, IssuingDistributionPoint},
    extensions::{
        BasicConstraints, DistributionPoint, DistributionPointName, KeyUsage,
        SequenceOfDistributionPoints,
    },
    name::{GeneralName, Name},
    oid,
};

use crate::{
    ops::{CryptoOps, VerificationCertificate},
    policy::Policy,
    ValidationError, ValidationErrorKind, ValidationResult,
};

fn crl_distribution_point_matches(
    crl_idp: IssuingDistributionPoint<'_, Asn1Read>,
    cert_dps: SequenceOfDistributionPoints<'_, Asn1Read>,
) -> bool {
    // The other match case here is nameRelativeToCRLIssuer, and RFC 5280 4.2.1.13 has a salient
    // recommendation on the subject:
    //
    // > Conforming CAs SHOULD NOT use nameRelativeToCRLIssuer to specify distribution point names.
    let Some(DistributionPointName::FullName(idp_names)) = crl_idp.distribution_point else {
        return false;
    };

    let idp_uris: Vec<&str> = idp_names
        .filter_map(|ref name| match name {
            // CABF 7.2.2.1: Non-uniformResourceIdentifier GeneralName types MUST NOT be included.
            GeneralName::UniformResourceIdentifier(ref uri) => Some(uri.0),
            _ => None,
        })
        .collect();

    // Check that a name in one of the cert's DPs matches one of the names in the iDP.
    for dp in cert_dps {
        // XX(tnytown): shouldn't be necessary, but rust-analyzer can't infer the type without?
        let _: &DistributionPoint<'_, Asn1Read> = &dp;

        // Same as above: reject anything that isn't a full name.
        let Some(DistributionPointName::FullName(dp_names)) = dp.distribution_point else {
            return false;
        };

        for name in dp_names {
            let GeneralName::UniformResourceIdentifier(uri) = name else {
                continue;
            };

            if idp_uris.contains(&uri.0) {
                return true;
            }
        }
    }

    false
}

/// Verifies that the scope of the CRL matches the certificate.
fn verify_crl_scope(crl: &CertificateRevocationList<'_>, cert: &Certificate<'_>) -> Option<()> {
    let crl_exts = crl.extensions().ok()?;

    // 5280 5.2.3: CRLNumber is required and must be non-critical.
    let crl_number_is_critical = crl_exts
        .get_extension(&oid::CRL_NUMBER_OID)
        .map(|ext| ext.critical)?;
    if crl_number_is_critical {
        return None;
    }

    // Check bits on the iDP extension. CABF 7.2.2.1 specifies that full and complete CRLs may omit
    // this extension; return successfully if this is the case.
    let Some(idp) = crl_exts
        .get_extension(&oid::ISSUING_DISTRIBUTION_POINT_OID)
        .and_then(|ext| ext.value::<IssuingDistributionPoint<'_, Asn1Read>>().ok())
    else {
        return Some(());
    };

    // Don't support reason code partitioning yet.
    if idp.only_some_reasons.is_some() {
        return None;
    }

    // CABF 7.2 disallows iCRLs.
    if idp.indirect_crl {
        return None;
    }

    let cert_exts = cert.extensions().ok()?;
    let cert_bc_ca = cert_exts
        .get_extension(&oid::BASIC_CONSTRAINTS_OID)
        .and_then(|e| e.value::<BasicConstraints>().ok())
        .map(|bc| bc.ca)
        .unwrap_or(false);

    // Check iDP following 5280 6.3.3(b)(2).

    // If onlyContainsUserCerts is asserted in the iDP CRL extension, verify that the certificate
    // does not include the basic constraints extension with the cA boolean asserted.
    if idp.only_contains_user_certs && cert_bc_ca {
        return None;
    }

    // If onlyContainsCACerts is asserted in the iDP CRL extension, verify that the certificate
    // includes the basic constraints extension with the cA boolean asserted.
    if idp.only_contains_ca_certs && !cert_bc_ca {
        return None;
    }

    // Verify that onlyContainsAttributeCerts is not asserted.
    if idp.only_contains_attribute_certs {
        return None;
    }

    let dps: SequenceOfDistributionPoints<'_, Asn1Read> = cert_exts
        .get_extension(&oid::CRL_DISTRIBUTION_POINTS_OID)?
        .value()
        .ok()?;

    // Check DPs (where the cert expects us to find CRLs) against iDP (where the CRL says it's from).
    if !crl_distribution_point_matches(idp, dps) {
        return None;
    }

    Some(())
}

/// A CRL alongside a map containing revocation information to enable fast lookups.
struct CrlMeta<'a> {
    crl: &'a CertificateRevocationList<'a>,
    serials: HashSet<asn1::BigInt<'a>>,
}

impl<'a> CrlMeta<'a> {
    fn load(crl: &'a CertificateRevocationList<'a>) -> Option<Self> {
        // We only interpret X.509 v2 CRLs.
        if crl.tbs_cert_list.version != Some(1) {
            return None;
        }

        // Check for any unrecognized critical extensions.
        for ext in crl.extensions().ok()?.iter() {
            if !ext.critical {
                continue;
            }

            match ext.extn_id {
                oid::ISSUING_DISTRIBUTION_POINT_OID => (),
                _ => return None,
            }
        }

        let mut serials = HashSet::new();
        let Some(crl_entries) = crl
            .tbs_cert_list
            .revoked_certificates
            .as_ref()
            .map(|e| e.unwrap_read().clone())
        else {
            // Allow empty CRLs.
            return Some(Self { crl, serials });
        };

        // Check extensions on CRL entries while populating the set.
        for entry in crl_entries.into_iter() {
            for ext in entry.extensions().ok()?.iter() {
                // We don't recognize any critical extensions.
                if ext.critical {
                    return None;
                }
            }

            // Insert and check for duplicates.
            if !serials.insert(entry.user_certificate) {
                return None;
            }
        }

        Some(Self { crl, serials })
    }
}

pub struct CrlRevocationChecker<'a> {
    by_issuer: HashMap<Name<'a>, CrlMeta<'a>>,
}

impl<'a> CrlRevocationChecker<'a> {
    pub fn is_revoked<'chain, B: CryptoOps>(
        &self,
        cert: &VerificationCertificate<'chain, B>,
        policy: &Policy<'_, B>,
    ) -> ValidationResult<'chain, bool, B> {
        let cert = cert.certificate();
        // Get the CRL out of our map of verified CRLs keyed by issuer.
        let CrlMeta { crl, serials } =
            self.by_issuer
                .get(&cert.tbs_cert.issuer)
                .ok_or(ValidationError::new(
                    ValidationErrorKind::RevocationNotDetermined(
                        "applicable CRL not found for certificate".to_owned(),
                    ),
                ))?;

        if verify_crl_scope(crl, cert).is_none() {
            return Err(ValidationError::new(
                ValidationErrorKind::RevocationNotDetermined(
                    "applicable CRL not correctly scoped to certificate".to_owned(),
                ),
            ));
        }

        // Check CRL against policy time.
        policy.permits_crl(crl)?;

        Ok(serials.contains(&cert.tbs_cert.serial))
    }

    /// Constructs a new revocation checker backed by CRLs in accordance with the RFC 5280 and CABF
    /// CRL profiles.
    ///
    /// Accepts issuers and their associated CRLs. Each [`CrlRevocationChecker`] instance
    /// must abide by the following constraints:
    /// - Must contain at most one CRL per issuer.
    /// - CRLs must not be partitioned by reason code.
    /// - CRLs must be direct: the CRL's issuer must match the issuer of its revokees.
    ///
    /// In other words, each CRL should be authoritative for its issuer for the duration of the
    /// CRL's effective window.
    pub fn new<B: CryptoOps>(
        ops: B,
        crls: impl IntoIterator<Item = (&'a Certificate<'a>, &'a CertificateRevocationList<'a>)>,
    ) -> Option<Self> {
        let mut by_issuer = HashMap::new();

        for (issuer, crl) in crls {
            // 5280 4.2.1.3: check keyUsage.cRLSign if keyUsage is present.
            if let Some(ext) = issuer.extensions().ok()?.get_extension(&oid::KEY_USAGE_OID) {
                let ku: KeyUsage<'_> = ext.value().ok()?;

                if !ku.crl_sign() {
                    return None;
                }
            }

            let key = ops.public_key(issuer).ok()?;
            ops.verify_crl_signed_by(crl, &key).ok()?;

            let meta = CrlMeta::load(crl)?;
            let issuer_name = issuer.tbs_cert.subject.clone();

            // Fail if we've already processed a CRL for this issuer.
            if by_issuer.insert(issuer_name, meta).is_some() {
                return None;
            }
        }

        Some(Self { by_issuer })
    }
}
