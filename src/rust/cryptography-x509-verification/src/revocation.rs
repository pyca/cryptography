// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::{HashMap, HashSet};

use cryptography_x509::{
    certificate::Certificate,
    common::Asn1Read,
    crl::{CertificateRevocationList, IssuingDistributionPoint},
    extensions::{
        BasicConstraints, DistributionPointName, Extensions, KeyUsage, SequenceOfDistributionPoints,
    },
    name::{GeneralName, Name},
    oid,
};

use crate::{
    ops::{CryptoOps, VerificationCertificate},
    policy::Policy,
    ValidationError, ValidationErrorKind, ValidationResult,
};

fn validate_distribution_point_uris<'a>(
    set: &mut HashSet<&'a str>,
    dp: Option<DistributionPointName<'a, Asn1Read>>,
) -> bool {
    // The other match case here is nameRelativeToCRLIssuer, and RFC 5280 4.2.1.13 has a salient
    // recommendation on the subject:
    //
    // > Conforming CAs SHOULD NOT use nameRelativeToCRLIssuer to specify distribution point names.
    let Some(DistributionPointName::FullName(idp_names)) = dp else {
        return false;
    };

    // CABF 7.2.2.1, 7.1.2.11.2: names in iDPs and CDPs must be of type uniformResourceIdentifier.
    for name in idp_names {
        match name {
            GeneralName::UniformResourceIdentifier(ref uri) => set.insert(uri.0),
            _ => return false,
        };
    }

    true
}

/// Verifies that the scope of the CRL (iDP) matches the certificate.
fn cert_dp_matches_idp<'a>(
    cert_exts: &Extensions<'a>,
    idp: IssuingDistributionPoint<'a, Asn1Read>,
) -> bool {
    let cert_bc_ca = cert_exts
        .get_extension(&oid::BASIC_CONSTRAINTS_OID)
        .and_then(|e| e.value::<BasicConstraints>().ok())
        .map(|bc| bc.ca)
        .unwrap_or(false);

    // Check iDP following 5280 6.3.3(b)(2).

    // If onlyContainsUserCerts is asserted in the iDP CRL extension, verify that the certificate
    // does not include the basic constraints extension with the cA boolean asserted.
    if idp.only_contains_user_certs && cert_bc_ca {
        return false;
    }

    // If onlyContainsCACerts is asserted in the iDP CRL extension, verify that the certificate
    // includes the basic constraints extension with the cA boolean asserted.
    if idp.only_contains_ca_certs && !cert_bc_ca {
        return false;
    }

    // Verify that onlyContainsAttributeCerts is not asserted.
    if idp.only_contains_attribute_certs {
        return false;
    }

    // Now, check that the iDP URIs match those in the certificate.
    let mut idp_uris = HashSet::new();
    if !validate_distribution_point_uris(&mut idp_uris, idp.distribution_point) {
        return false;
    };

    let Some(cert_dps) = cert_exts
        .get_extension(&oid::CRL_DISTRIBUTION_POINTS_OID)
        .and_then(|ext| {
            ext.value::<SequenceOfDistributionPoints<'_, Asn1Read>>()
                .ok()
        })
    else {
        return false;
    };

    // NOTE(tnytown): a faster way to do this might be to short-circuit when we find a matching name
    // in a CDP; in the interest of strictness, we process every DP and its associated names to
    // ensure that the certificate has the correct shape.
    let mut dp_uris = HashSet::new();
    for dp in cert_dps {
        if !validate_distribution_point_uris(&mut dp_uris, dp.distribution_point) {
            return false;
        };
    }

    !idp_uris.is_disjoint(&dp_uris)
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

        let crl_exts = crl.extensions().ok()?;

        // 5280 5.2.3: CRLNumber is required.
        crl_exts.get_extension(&oid::CRL_NUMBER_OID)?;

        // Check bits on the iDP extension. CABF 7.2.2.1 specifies that full and complete CRLs may omit
        // this extension; do nothing if it is missing.
        if let Some(ref idp) = crl_exts
            .get_extension(&oid::ISSUING_DISTRIBUTION_POINT_OID)
            .and_then(|ext| ext.value::<IssuingDistributionPoint<'_, Asn1Read>>().ok())
        {
            // Don't support reason code partitioning yet.
            if idp.only_some_reasons.is_some() {
                return None;
            }

            // CABF 7.2 disallows iCRLs.
            if idp.indirect_crl {
                return None;
            }
        }

        // Check for any unrecognized critical extensions.
        for ext in crl_exts.iter() {
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

        // Perform a scoping check on the iDP if it exists.
        if let Some(idp) = crl
            .extensions()
            .ok()
            .and_then(|exts| exts.get_extension(&oid::ISSUING_DISTRIBUTION_POINT_OID))
            .and_then(|ext| ext.value::<IssuingDistributionPoint<'_, _>>().ok())
        {
            let cert_exts = cert.extensions()?;
            if !cert_dp_matches_idp(&cert_exts, idp) {
                return Err(ValidationError::new(
                    ValidationErrorKind::RevocationNotDetermined(
                        "applicable CRL not correctly scoped to certificate".to_owned(),
                    ),
                ));
            }
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
            // 5280 4.2.1.3 says to check keyUsage.cRLSign if keyUsage is present.
            // Diverge a little bit: CABF (and our policy engine) requires keyUsage on issuers,
            // so don't allow for missing keyUsage here either.
            let key_usage_set = issuer
                .extensions()
                .ok()?
                .get_extension(&oid::KEY_USAGE_OID)
                .and_then(|ku| ku.value::<KeyUsage<'_>>().ok())
                .map(|ku| ku.crl_sign())
                .unwrap_or(false);
            if !key_usage_set {
                return None;
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

#[cfg(test)]
mod tests {
    use super::CrlRevocationChecker;
    use crate::{
        certificate::tests::ca_pem,
        ops::tests::{cert, crl, NullOps},
        revocation::CrlMeta,
    };

    fn crl_pem() -> pem::Pem {
        // From vectors/cryptography_vectors/x509/custom/crl_bad_version.pem
        pem::parse(
            "-----BEGIN X509 CRL-----
MIIBpzCBkAIBAjANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzETMBEGA1UE
CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJ
Qm9yaW5nU1NMFw0xNjA5MjYxNTEwNTVaFw0xNjEwMjYxNTEwNTVaoA4wDDAKBgNV
HRQEAwIBATANBgkqhkiG9w0BAQsFAAOCAQEAnrBKKgvd9x9zwK9rtUvVeFeJ7+LN
ZEAc+a5oxpPNEsJx6hXoApYEbzXMxuWBQoCs5iEBycSGudct21L+MVf27M38KrWo
eOkq0a2siqViQZO2Fb/SUFR0k9zb8xl86Zf65lgPplALun0bV/HT7MJcl04Tc4os
dsAReBs5nqTGNEd5AlC1iKHvQZkM//MD51DspKnDpsDiUVi54h9C1SpfZmX8H2Vv
diyu0fZ/bPAM3VAGawatf/SyWfBMyKpoPXEG39oAzmjjOj8en82psn7m474IGaho
/vBbhl1ms5qQiLYPjm4YELtnXQoFyC72tBjbdFd/ZE9k4CNKDbxFUXFbkw==
-----END X509 CRL-----",
        )
        .unwrap()
    }

    // Limbo tests exercise from Python which hits the check in load_der_x509_crl, missing the
    // additional check in the Rust surface.
    #[test]
    fn rejects_unsupported_crl_version() {
        let issuer_pem = ca_pem();
        let issuer = cert(&issuer_pem);
        let crl_pem = crl_pem();
        let crl = crl(&crl_pem);

        assert_eq!(crl.tbs_cert_list.version, Some(2));
        assert!(CrlMeta::load(&crl).is_none());
        assert!(CrlRevocationChecker::new(NullOps, [(&issuer, &crl)]).is_none());
    }
}
