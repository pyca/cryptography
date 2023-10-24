// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]

pub mod certificate;
pub mod ops;
pub mod policy;
pub mod trust_store;
pub mod types;

use std::collections::HashSet;

use crate::certificate::cert_is_self_issued;
use crate::types::{DNSConstraint, IPAddress, IPConstraint};
use crate::ApplyNameConstraintStatus::{Applied, Skipped};
use cryptography_x509::extensions::Extensions;
use cryptography_x509::{
    certificate::Certificate,
    extensions::{
        DuplicateExtensionsError, NameConstraints, SequenceOfSubtrees, SubjectAlternativeName,
    },
    name::GeneralName,
    oid::{NAME_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID},
};
use ops::CryptoOps;
use policy::{Policy, PolicyError};
use trust_store::Store;
use types::DNSName;

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    Policy(PolicyError),
}

impl From<PolicyError> for ValidationError {
    fn from(value: PolicyError) -> Self {
        ValidationError::Policy(value)
    }
}

impl From<asn1::ParseError> for ValidationError {
    fn from(value: asn1::ParseError) -> Self {
        ValidationError::Policy(PolicyError::Malformed(value))
    }
}

impl From<DuplicateExtensionsError> for ValidationError {
    fn from(value: DuplicateExtensionsError) -> Self {
        ValidationError::Policy(PolicyError::DuplicateExtension(value))
    }
}

#[derive(Default)]
pub struct AccumulatedNameConstraints<'a> {
    pub permitted: Vec<GeneralName<'a>>,
    pub excluded: Vec<GeneralName<'a>>,
}

pub type Chain<'c> = Vec<Certificate<'c>>;
type IntermediateChain<'c> = (Chain<'c>, AccumulatedNameConstraints<'c>);

pub fn verify<'leaf: 'chain, 'inter: 'chain, 'store: 'chain, 'chain, B: CryptoOps>(
    leaf: &'chain Certificate<'leaf>,
    intermediates: impl IntoIterator<Item = Certificate<'inter>>,
    policy: &Policy<'_, B>,
    store: &'chain Store<'store>,
) -> Result<Chain<'chain>, ValidationError> {
    let builder = ChainBuilder::new(HashSet::from_iter(intermediates), policy, store);

    builder.build_chain(leaf)
}

struct ChainBuilder<'a, 'inter, 'store, B: CryptoOps> {
    intermediates: HashSet<Certificate<'inter>>,
    policy: &'a Policy<'a, B>,
    store: &'a Store<'store>,
}

// When applying a name constraint, we need to distinguish between a few different scenarios:
// * `Applied(true)`: The name constraint is the same type as the SAN and matches.
// * `Applied(false)`: The name constraint is the same type as the SAN and does not match.
// * `Skipped`: The name constraint is a different type to the SAN.
enum ApplyNameConstraintStatus {
    Applied(bool),
    Skipped,
}

impl ApplyNameConstraintStatus {
    fn is_applied(&self) -> bool {
        matches!(self, Applied(_))
    }

    fn is_match(&self) -> bool {
        match self {
            Applied(a) => *a,
            _ => false,
        }
    }
}

impl<'a, 'inter, 'store, 'leaf, 'chain, 'work, B: CryptoOps> ChainBuilder<'a, 'inter, 'store, B>
where
    'leaf: 'chain,
    'inter: 'chain,
    'store: 'chain,
    'work: 'leaf + 'inter,
    'chain: 'work,
{
    fn new(
        intermediates: HashSet<Certificate<'inter>>,
        policy: &'a Policy<'a, B>,
        store: &'a Store<'store>,
    ) -> Self {
        Self {
            intermediates,
            policy,
            store,
        }
    }

    fn potential_issuers(
        &'a self,
        cert: &'a Certificate<'work>,
    ) -> impl Iterator<Item = &'a Certificate<'work>> + '_ {
        // TODO: Optimizations:
        // * Use a backing structure that allows us to search by name
        //   rather than doing a linear scan
        // * Search by AKI and other identifiers?
        self.intermediates
            .iter()
            // NOTE: The intermediate set isn't allowed to offer a self-signed
            // certificate as a candidate, since self-signed certs can only
            // be roots.
            .filter(|&candidate| *candidate != *cert)
            .chain(self.store.iter())
            .filter(|&candidate| candidate.subject() == cert.issuer())
    }

    fn build_name_constraints_subtrees(
        &self,
        subtrees: SequenceOfSubtrees<'work>,
    ) -> Vec<GeneralName<'work>> {
        subtrees.unwrap_read().clone().map(|x| x.base).collect()
    }

    fn build_name_constraints(
        &self,
        constraints: &mut AccumulatedNameConstraints<'work>,
        working_cert: &'a Certificate<'work>,
    ) -> Result<(), ValidationError> {
        let extensions: Extensions<'work> = working_cert.extensions()?;
        if let Some(nc) = extensions.get_extension(&NAME_CONSTRAINTS_OID) {
            let nc: NameConstraints<'work> = nc.value()?;
            if let Some(permitted_subtrees) = nc.permitted_subtrees {
                constraints
                    .permitted
                    .extend(self.build_name_constraints_subtrees(permitted_subtrees));
            }
            if let Some(excluded_subtrees) = nc.excluded_subtrees {
                constraints
                    .excluded
                    .extend(self.build_name_constraints_subtrees(excluded_subtrees));
            }
        }
        Ok(())
    }

    fn apply_name_constraint(
        &self,
        constraint: &GeneralName<'work>,
        san: &GeneralName<'_>,
    ) -> Result<ApplyNameConstraintStatus, ValidationError> {
        match (constraint, san) {
            (GeneralName::DNSName(pattern), GeneralName::DNSName(name)) => {
                if let Some(pattern) = DNSConstraint::new(pattern.0) {
                    let name = DNSName::new(name.0).unwrap();
                    Ok(Applied(pattern.matches(&name)))
                } else {
                    Err(PolicyError::Other("malformed DNS name constraint").into())
                }
            }
            (GeneralName::IPAddress(pattern), GeneralName::IPAddress(name)) => {
                if let Some(pattern) = IPConstraint::from_bytes(pattern) {
                    let name = IPAddress::from_bytes(name).unwrap();
                    Ok(Applied(pattern.matches(&name)))
                } else {
                    Err(PolicyError::Other("malformed IP name constraint").into())
                }
            }
            _ => Ok(Skipped),
        }
    }

    fn apply_name_constraints(
        &self,
        constraints: &AccumulatedNameConstraints<'work>,
        working_cert: &Certificate<'work>,
    ) -> Result<(), ValidationError> {
        let extensions = working_cert.extensions()?;
        if let Some(sans) = extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID) {
            let sans: SubjectAlternativeName<'_> = sans.value()?;
            for san in sans.clone() {
                // If there are no applicable constraints, the SAN is considered valid so let's default to true.
                let mut permit = true;
                for c in constraints.permitted.iter() {
                    let status = self.apply_name_constraint(c, &san)?;
                    if status.is_applied() {
                        permit = status.is_match();
                        if permit {
                            break;
                        }
                    }
                }
                if !permit {
                    return Err(
                        PolicyError::Other("no permitted name constraints matched SAN").into(),
                    );
                }
                for c in constraints.excluded.iter() {
                    let status = self.apply_name_constraint(c, &san)?;
                    if status.is_match() {
                        return Err(
                            PolicyError::Other("excluded name constraint matched SAN").into()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn build_chain_inner(
        &self,
        working_cert: &'a Certificate<'work>,
        current_depth: u8,
        is_leaf: bool,
    ) -> Result<IntermediateChain<'work>, ValidationError> {
        if current_depth > self.policy.max_chain_depth {
            return Err(PolicyError::Other("chain construction exceeds max depth").into());
        }

        // Look in the store's root set to see if the working cert is listed.
        // If it is, we've reached the end.
        //
        // Observe that no issuer connection or signature verification happens
        // here: inclusion in the root set implies a trust relationship,
        // even if the working certificate is an EE or intermediate CA.
        if self.store.contains(working_cert) {
            let mut constraints = AccumulatedNameConstraints::default();
            self.build_name_constraints(&mut constraints, working_cert)?;
            return Ok((vec![working_cert.clone()], constraints));
        }

        // Otherwise, we collect a list of potential issuers for this cert,
        // and continue with the first that verifies.
        for issuing_cert_candidate in self.potential_issuers(working_cert) {
            // A candidate issuer is said to verify if it both
            // signs for the working certificate and conforms to the
            // policy.
            if let Ok(next_depth) =
                self.policy
                    .valid_issuer(issuing_cert_candidate, working_cert, current_depth)
            {
                let result = self.build_chain_inner(issuing_cert_candidate, next_depth, false);
                if let Ok(result) = result {
                    let (remaining, mut constraints) = result;
                    // Name constraints are not applied to self-issued certificates unless they're
                    // the leaf certificate in the chain.
                    //
                    // NOTE: We can't simply check the `current_depth` since self-issued
                    // certificates don't increase the working depth.
                    let skip_name_constraints = cert_is_self_issued(working_cert) && !is_leaf;
                    if skip_name_constraints
                        || self
                            .apply_name_constraints(&constraints, working_cert)
                            .is_ok()
                    {
                        let mut chain: Vec<Certificate<'work>> = vec![working_cert.clone()];
                        chain.extend(remaining);
                        self.build_name_constraints(&mut constraints, working_cert)?;
                        return Ok((chain, constraints));
                    }
                }
            }
        }

        // We only reach this if we fail to hit our base case above, or if
        // a chain building step fails to find a next valid certificate.
        Err(PolicyError::Other("chain construction exhausted all candidates").into())
    }

    fn build_chain(
        &self,
        leaf: &'chain Certificate<'leaf>,
    ) -> Result<Chain<'chain>, ValidationError> {
        // Before anything else, check whether the given leaf cert
        // is well-formed according to our policy (and its underlying
        // certificate profile).
        //
        // In the case that the leaf is an EE, this includes a check
        // against the EE cert's SANs.
        self.policy.permits_leaf(leaf)?;

        // NOTE: We start the chain depth at 1, indicating the EE.
        let result = self.build_chain_inner(leaf, 1, true);
        match result {
            Ok(result) => {
                let (chain, _) = result;
                Ok(chain)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{ops::tests::NullOps, types::DNSName};

    #[macro_export]
    macro_rules! cert {
        ($pem:literal) => {{
            let parsed = Box::leak(Box::new(pem::parse($pem).unwrap()));
            asn1::parse_single::<Certificate<'static>>(&parsed.contents()).unwrap()
        }};
    }

    #[test]
    fn test_verify_trivial() {
        let ee = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIFJDCCBAygAwIBAgISBCjrgR1TEHICklNpQDzj1PqPMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMzA1MjkxODQ0MDBaFw0yMzA4MjcxODQzNTlaMBoxGDAWBgNVBAMT
D2NyeXB0b2dyYXBoeS5pbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AObo0GReSiFFL4eMlFHutcV+LpLDorPpzzFxxJsXhrm19GyWYHdr4ml7GIAEjqI7
QZp0aYw1lmtHwgNnaRySU+aWj6LMWI/rIP5rXZYIZLyXSfLbHP0xlfYEvcrcprOm
Au0YuQgy3TBO0qz6FKx5PtfbDc7p/LYD5tnG5NkbQ4o+7Ko361w787WSb8OV5NFd
nPqSeIjwxqSy62G6oOHL4wRFDTCOdNjHeYJnPC0L3P9qkGeC6zjqt2h8Q+GE9zNQ
enqaEOeBIZo46mti6Tvzzc7dqILw1ATqIXJdjwABzuT8Ob34/LsPorLQoRP1+YHF
++D2JyyvYKM/aFpQI+HHfGUCAwEAAaOCAkowggJGMA4GA1UdDwEB/wQEAwIFoDAd
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNV
HQ4EFgQUOtGXHs6fLoMQEwjlwSu88r4qLf0wHwYDVR0jBBgwFoAUFC6zF7dYVsuu
UAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8v
cjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9y
Zy8wGgYDVR0RBBMwEYIPY3J5cHRvZ3JhcGh5LmlvMEwGA1UdIARFMEMwCAYGZ4EM
AQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0
c2VuY3J5cHQub3JnMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHcAtz77JN+cTbp1
8jnFulj0bF38Qs96nzXEnh0JgSXttJkAAAGIaQn30wAABAMASDBGAiEAglrQJj8G
a7/1upmZ2Is6AqPT9pQpSty0sH4PgnqyQxICIQDEpKnk6Rt6KzvEpIIIEtXgrYx+
crerlx4SQVQbnwfz0gB1AHoyjFTYty22IOo44FIe6YQWcDIThU070ivBOlejUutS
AAABiGkJ9+sAAAQDAEYwRAIgaLwFE4CfhV09wq5IR5zmo/90y5OQJ2MnW5gpRZZh
s4YCICEAGxUN/f95xFmxOCfqXv3SEozwkrMHA33abVjCQiaGMA0GCSqGSIb3DQEB
CwUAA4IBAQBSTN5U/3yp6cGMBXlS5WcrB/XOY6TtxPmeSvLM3vqNbpRGu1JOFFtn
31eweHOTj66GWowSy9+uAhp1V9Uf0hoJMa/b+CkCelyJN4QZCcMfhKrPAD4prbHa
GYFaLo5SQqkK1hYHo9LH+qhaOBx9hF5aLrGbEFWXQE9/W7KSeCzz6LBLw9xVrB2v
NTLlXXt5tUiczOIzge5KGaSQr5wgc1viddcRsYuZjtgWlqJ5E5QcZxD8xLTfBe5W
9vl/k1CB4CZ1IG8Sa9+n91Kxm3HTLL6TcrEOutChwMfZfrLH/piWoRQxezCpn82N
RaeeHd1Bv3oH3SeVJUHLxgzUv/dh6GSi
-----END CERTIFICATE-----
"
        );

        let intermediate = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP
R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx
sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm
NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg
Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG
/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W
PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl
ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz
CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm
lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4
avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2
yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O
yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids
hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+
HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv
MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX
nLRbwHOoq7hHwg==
-----END CERTIFICATE-----
"
        );

        let root = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
"
        );

        let store = Store::new([root.clone()]);
        let ops = NullOps {};
        let time = asn1::DateTime::new(2023, 7, 10, 0, 0, 0).unwrap();
        let policy: Policy<'_, _> = Policy::new(
            ops,
            Some(policy::Subject::DNS(
                DNSName::new("cryptography.io").unwrap(),
            )),
            time,
        );

        let chain = verify(&ee, [intermediate.clone()], &policy, &store).unwrap();
        assert_eq!(chain.len(), 3);
        assert!(chain[0] == ee);
        assert!(chain[1] == intermediate);
        assert!(chain[2] == root);
    }

    #[test]
    fn test_verify_trivial_missing_root() {
        let ee = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIFJDCCBAygAwIBAgISBCjrgR1TEHICklNpQDzj1PqPMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMzA1MjkxODQ0MDBaFw0yMzA4MjcxODQzNTlaMBoxGDAWBgNVBAMT
D2NyeXB0b2dyYXBoeS5pbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AObo0GReSiFFL4eMlFHutcV+LpLDorPpzzFxxJsXhrm19GyWYHdr4ml7GIAEjqI7
QZp0aYw1lmtHwgNnaRySU+aWj6LMWI/rIP5rXZYIZLyXSfLbHP0xlfYEvcrcprOm
Au0YuQgy3TBO0qz6FKx5PtfbDc7p/LYD5tnG5NkbQ4o+7Ko361w787WSb8OV5NFd
nPqSeIjwxqSy62G6oOHL4wRFDTCOdNjHeYJnPC0L3P9qkGeC6zjqt2h8Q+GE9zNQ
enqaEOeBIZo46mti6Tvzzc7dqILw1ATqIXJdjwABzuT8Ob34/LsPorLQoRP1+YHF
++D2JyyvYKM/aFpQI+HHfGUCAwEAAaOCAkowggJGMA4GA1UdDwEB/wQEAwIFoDAd
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNV
HQ4EFgQUOtGXHs6fLoMQEwjlwSu88r4qLf0wHwYDVR0jBBgwFoAUFC6zF7dYVsuu
UAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8v
cjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9y
Zy8wGgYDVR0RBBMwEYIPY3J5cHRvZ3JhcGh5LmlvMEwGA1UdIARFMEMwCAYGZ4EM
AQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0
c2VuY3J5cHQub3JnMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHcAtz77JN+cTbp1
8jnFulj0bF38Qs96nzXEnh0JgSXttJkAAAGIaQn30wAABAMASDBGAiEAglrQJj8G
a7/1upmZ2Is6AqPT9pQpSty0sH4PgnqyQxICIQDEpKnk6Rt6KzvEpIIIEtXgrYx+
crerlx4SQVQbnwfz0gB1AHoyjFTYty22IOo44FIe6YQWcDIThU070ivBOlejUutS
AAABiGkJ9+sAAAQDAEYwRAIgaLwFE4CfhV09wq5IR5zmo/90y5OQJ2MnW5gpRZZh
s4YCICEAGxUN/f95xFmxOCfqXv3SEozwkrMHA33abVjCQiaGMA0GCSqGSIb3DQEB
CwUAA4IBAQBSTN5U/3yp6cGMBXlS5WcrB/XOY6TtxPmeSvLM3vqNbpRGu1JOFFtn
31eweHOTj66GWowSy9+uAhp1V9Uf0hoJMa/b+CkCelyJN4QZCcMfhKrPAD4prbHa
GYFaLo5SQqkK1hYHo9LH+qhaOBx9hF5aLrGbEFWXQE9/W7KSeCzz6LBLw9xVrB2v
NTLlXXt5tUiczOIzge5KGaSQr5wgc1viddcRsYuZjtgWlqJ5E5QcZxD8xLTfBe5W
9vl/k1CB4CZ1IG8Sa9+n91Kxm3HTLL6TcrEOutChwMfZfrLH/piWoRQxezCpn82N
RaeeHd1Bv3oH3SeVJUHLxgzUv/dh6GSi
-----END CERTIFICATE-----
"
        );

        let intermediate = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP
R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx
sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm
NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg
Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG
/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W
PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl
ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz
CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm
lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4
avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2
yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O
yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids
hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+
HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv
MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX
nLRbwHOoq7hHwg==
-----END CERTIFICATE-----
"
        );

        let store = Store::new([]);
        let ops = NullOps {};
        let time = asn1::DateTime::new(2023, 7, 10, 0, 0, 0).unwrap();
        let policy: Policy<'_, _> = Policy::new(
            ops,
            Some(policy::Subject::DNS(
                DNSName::new("cryptography.io").unwrap(),
            )),
            time,
        );
        assert_eq!(
            verify(&ee, [intermediate.clone()], &policy, &store).err(),
            Some(PolicyError::Other("chain construction exhausted all candidates").into())
        );
    }
}
