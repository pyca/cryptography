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

use cryptography_x509::certificate::Certificate;
use ops::CryptoOps;
use policy::{Policy, PolicyError};
use trust_store::Store;

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    Policy(PolicyError),
}

impl From<PolicyError> for ValidationError {
    fn from(value: PolicyError) -> Self {
        ValidationError::Policy(value)
    }
}

pub type Chain<'c> = Vec<Certificate<'c>>;

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

    fn build_chain_inner(
        &self,
        working_cert: &Certificate<'work>,
        current_depth: u8,
    ) -> Result<Chain<'work>, ValidationError> {
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
            return Ok(vec![working_cert.clone()]);
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
                let mut chain = vec![working_cert.clone()];
                chain.extend(self.build_chain_inner(issuing_cert_candidate, next_depth)?);
                return Ok(chain);
            }
        }

        // We only reach this if we fail to hit our base case above, or if
        // a chain building step fails to find a next valid certificate.
        Err(PolicyError::Other("chain construction exhausted all candidates").into())
    }

    fn build_chain(&self, leaf: &Certificate<'leaf>) -> Result<Chain<'chain>, ValidationError> {
        // Before anything else, check whether the given leaf cert
        // is well-formed according to our policy (and its underlying
        // certificate profile).
        //
        // In the case that the leaf is an EE, this includes a check
        // against the EE cert's SANs.
        self.policy.permits_leaf(leaf)?;

        // NOTE: We start the chain depth at 1, indicating the EE.
        self.build_chain_inner(leaf, 1)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ops::tests::NullOps;

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
MIIDMTCCAhmgAwIBAgIUcNqk/7PML+7lLXVcx3gjsq65hM4wDQYJKoZIhvcNAQEL
BQAwLDEqMCgGA1UEAwwheDUwOS1saW1iby1pbnRlcm1lZGlhdGUtcGF0aGxlbi0w
MCAXDTY5MTIzMTE5MDAwMFoYDzI5NjkwNTAyMTkwMDAwWjAYMRYwFAYDVQQDDA14
NTA5LWxpbWJvLWVlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAunA2
HOgxI+I/RYPFB+4eAEz36KqDLCkGHYi4SPa5pX/hD+F+aEFWmboqdwgSpgRks8LS
a9dZO8Fg+Or8HQ6WFOrAtWcWX2KlRXSF6A7M0lUPVrSmmgcwp6yOyMAVCEumRk7l
lEG9TJSK0pInEC2gAmRY95sTiGYgyu/0OFbZk6rZRJtpq617d84D6EkJz80I9XIa
dejC1/V7YAbWIvJ+gJDvoQ0zz9//bZkDNHVRP/8rhMvo9JCBZoCqPohDQg/kJzk0
0Dw1bUiGmnyGOOyjjBVjG0BpZ5cJeYeIR+vBKjbdskwf+fNRAfgg3mx/GTBkpAWb
TdxOdON0VlNTTLSThwIDAQABo10wWzAdBgNVHQ4EFgQUYEyaR1+cGsp4ksddTVm4
2vR5mXYwHwYDVR0jBBgwFoAUHyKN5Jy/CWcuUTv4icRmQ9lqy20wDAYDVR0TAQH/
BAIwADALBgNVHQ8EBAMCB4AwDQYJKoZIhvcNAQELBQADggEBAB8/04XbnzEumwLE
BwrG8ddJw09M9bfyHZE3o2fP3axfoCmPb148W0EKjd3/ta0C0IS6FSSAZjE0omQy
PFB5R2VyjR9/MSP0CbRu/kgku8yUzTA8XuJjUWwCT+JYxP7peOAIBoKFJpuHy4dq
5omfndXDKmVUzzWSUhPMIFrlk0QX/V7fC3LAMwtjuhdJ7KlrNVyYUuOpYgS0jTYQ
BpcoQFqXRmO2v1kO+A8KIO9+ZWDnOP9ma1YFbrHfPU9Px5j5OexDQ+nJ+2iLiHdo
DA9R5Sse+51/INk+4ZNZxO4BuoSNYz991KGUX/3w5EF7vsC1DX6Gf8E8HCMd2sYR
8S06Qm0=
-----END CERTIFICATE-----
"
        );

        let intermediate = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIEOTCCAiGgAwIBAgIUR2Y0g1z8TPo2nJguc6VquNHd5QwwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPeDUwOS1saW1iby1yb290MCAXDTY5MTIzMTE5MDAwMFoY
DzI5NjkwNTAyMTkwMDAwWjAsMSowKAYDVQQDDCF4NTA5LWxpbWJvLWludGVybWVk
aWF0ZS1wYXRobGVuLTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCN
oX/AIxNzzgD9D9Jkyx0nj2bNPblIYkl3UZK9v8+oTAkDkkk9fwZJfrzgNk7DYZ7L
CN9urM5NmQkmEb0h4iBHwxZ2srfSX5Q2406FqZe/naDvPRS6SH06nYlEAyFM0AYq
hyfQq/eNpqHv+/2HPRYmoBAD0mnDPF50aI6p5EpLt+HRRp4aoJDZCLuat1YnEm4U
eEqRQPdJNjEAqU7rpoJ3I0tDQMg8VwZbtIQizfFAgq+iaoOVFtywCnD6C6GmLNXr
uFrBSii0GBk1Wj/ilORzE6y0CQQB+0b0pw1qXvWhnDh9KmIrUGng6rhEqn9M+ygB
G0OX+9bOrqe7DMG9wVKrAgMBAAGjYzBhMB0GA1UdDgQWBBQfIo3knL8JZy5RO/iJ
xGZD2WrLbTAfBgNVHSMEGDAWgBQk6STcTVDVaZDL0bPuPX6jOckpLTASBgNVHRMB
Af8ECDAGAQH/AgEAMAsGA1UdDwQEAwICBDANBgkqhkiG9w0BAQsFAAOCAgEA4KB4
ZLZsoKnY/bOKZmsT8hYVlzlFWCjitKt0wW5oQ888xB6mRuF7RN4UB4vS+wGsxD+U
Uruv0wfehEfuljN9N67pKpzE38ZzbvDuyhCHTGl/swLVlASWQPdPIG/fba/SFDqC
zvCQ2O1EZCNsixw2EVi6u/9CJQPmTab6kgQE0z6R1Xsd5Jr8FkG3funRtbeKAIyG
Gal8jBztw7ND06B+NlTSUK7S8nASK1FF8UXl9eDzkgc///NEF3BN4GWDE1wqv4KD
d3KAhCC3Jc8pjVnkKhLT5JHc7Xm4wI9NTM5Z6OU9dazUbg1ZPSxny8ZLym+6uTaz
wiDfWSDiuJFs7hvAeSZxJ9YAqqtATMaDaidSZGg3hFsXlrZ55J6MgxMw0J2Yelvv
/1dTUaNSH5E8o4y2EDZDY+F6w4qyrSv8Y/LGCjAqA+2KyZ5UYwTvAZBmW8aex1kc
t4nmFaYww8mXjV0BKT8IpocQwEg0nCTGFBcym+JQ5gsZDrVo5tpwFh0uDMnCp4ZW
9pvsY4dYKErjakjVxNfm3zucWb+i87m0N+XkosGshvZzCyiAJllZvIAz9rYGlgpL
lIxFcUftR94ANsows30zT+mkrh9YotLzKzTfL7QGd8+MIbahfasLY91UISP90ExR
iVjMQ19R8XwBE6n9t+BePjjvfF5ws+ahgpjx1AM=
-----END CERTIFICATE-----
"
        );

        let root = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIFAzCCAuugAwIBAgIULk/1FzjhdjPggYD8EUdUtMKIXQIwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPeDUwOS1saW1iby1yb290MCAXDTY5MTIzMTE5MDAwMFoY
DzI5NjkwNTAyMTkwMDAwWjAaMRgwFgYDVQQDDA94NTA5LWxpbWJvLXJvb3QwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDjaj2hSumOoxmHtQmAcR907Whw
2xHWQLa+v9mcsJbPMu2rwwhEs6MYWB2U3YV8BRtdLTFwUm7+JLZv9KSdk440Z5Ts
Ohm8XtieZRI2CEs4ypFyT15jDfY4T7U49mTSuZ9JuoFlsWrhm6R8+4xmkto/PTUr
x+xwgCyHPJlfxIQg5jlpwyoUK+Yl1h1moAyvWJBz5cUj+FENrXvwhvhfoBEo42Q7
LRU1st9LBnR3rvpUbd2BcABsXIqIyAd+Lu57bhFZ+abLnhVa7JNOeucMZ7BWH9N4
RSZn3iXmyOElpB2h4Us2Phzj9X6flfWCiHGPHnMs+Ndz4oQ3OScQcEZ3bMIJ3fwy
c5pnNr9Eq1f+uKNXfq7IXyg45Ho7iVhuk4ZpAaqAyKFiryusqYDBjHnWkiIbE2dX
aOTk1SQNuYOj3JhrwDFgfdZ+0mtWXW7Y/V93Dx1n0EkIoRahVCOkxGBm+a6Mr3G+
PqFAPioKOgjB9DI8uGtVA9YjwE0bXLeIuMswL5LGdo4ULhaqpHmhLDnO3DFGT5x4
jgbT1r+K/N7lPIpkrcXAIsCzuQ73eUlo6anrO+WrJ/L99rRAbWKGAKN2HO1N+x/K
weVRCL794ZXABqf9HmHxB0MlRLEBfOjcUmTghlPsmYMI47Sjrf0IdfFgZ3XU9MLP
HZ0U1J2LKGqi4PUqbwIDAQABoz8wPTAdBgNVHQ4EFgQUJOkk3E1Q1WmQy9Gz7j1+
oznJKS0wDwYDVR0TAQH/BAUwAwEB/zALBgNVHQ8EBAMCAgQwDQYJKoZIhvcNAQEL
BQADggIBAF/+zaqgfk5+AughIdfUDt+BspxDcp17Mv1O0UlbdfitFbQrJmLcz8qs
ZTYKZ3rcIZMEXUPVB64UgAd5QGa6Xb8wqYy93PuZoeB65KA3gPKOlRVo881FD4iT
Cb/ztZnHSpyDzYtyl5ECmeuJgEybRbZMcxovBngaFunI0K2+q4OzApak0hj/4oii
X6DAA25og2oM2iHEhG7eaemBxp62Lmboew4tKV8Sa8uwy8RxWJwRYlVkcI8uBFep
otfno/4IALx0nyXmEyRnLT6NNwNMakvf/95xU7qqn25s0xF+0G1EOIPma5pCBIF7
Y+kS2JaS4uhI66mrDTEvwtrDA/zNwPl6C3kHZlaRYiFTNxXeTfZKO+pA49ww0GzK
56KVef2E0d2zeEwZ2S5baGMtI1KssxY7eQIPY8cidUdaCeFQE/NKkGnOLVqT/LNF
gpkjybz/BQmGBCTQI5UWDj49UPoRVP8gXC0TyIPRIeITpXSmnpiDn4gPqC1+Z7jA
lJu1dP3ITd84CVkhuHOe9oLtECWSQENKxfEY+145iqHsgsG8Vim3tZyYJsWI5V0x
utv77PsVLZNG9QiyDMKbkVFk9+BzOnXWpFxyEys9A5HNBn1pVp30lu0EMqhChoR6
NlIpBxyLOUUx0e7+ooHYTUm9rNHmAYadjwNk3phoRzSQHhAQFjVQ
-----END CERTIFICATE-----
"
        );

        let store = Store::new([root.clone()]);
        let ops = NullOps {};
        let time = asn1::DateTime::new(2023, 1, 1, 0, 0, 0).unwrap();
        let policy: Policy<'_, _> = Policy::new(ops, None, time);

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
MIIDMTCCAhmgAwIBAgIUcNqk/7PML+7lLXVcx3gjsq65hM4wDQYJKoZIhvcNAQEL
BQAwLDEqMCgGA1UEAwwheDUwOS1saW1iby1pbnRlcm1lZGlhdGUtcGF0aGxlbi0w
MCAXDTY5MTIzMTE5MDAwMFoYDzI5NjkwNTAyMTkwMDAwWjAYMRYwFAYDVQQDDA14
NTA5LWxpbWJvLWVlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAunA2
HOgxI+I/RYPFB+4eAEz36KqDLCkGHYi4SPa5pX/hD+F+aEFWmboqdwgSpgRks8LS
a9dZO8Fg+Or8HQ6WFOrAtWcWX2KlRXSF6A7M0lUPVrSmmgcwp6yOyMAVCEumRk7l
lEG9TJSK0pInEC2gAmRY95sTiGYgyu/0OFbZk6rZRJtpq617d84D6EkJz80I9XIa
dejC1/V7YAbWIvJ+gJDvoQ0zz9//bZkDNHVRP/8rhMvo9JCBZoCqPohDQg/kJzk0
0Dw1bUiGmnyGOOyjjBVjG0BpZ5cJeYeIR+vBKjbdskwf+fNRAfgg3mx/GTBkpAWb
TdxOdON0VlNTTLSThwIDAQABo10wWzAdBgNVHQ4EFgQUYEyaR1+cGsp4ksddTVm4
2vR5mXYwHwYDVR0jBBgwFoAUHyKN5Jy/CWcuUTv4icRmQ9lqy20wDAYDVR0TAQH/
BAIwADALBgNVHQ8EBAMCB4AwDQYJKoZIhvcNAQELBQADggEBAB8/04XbnzEumwLE
BwrG8ddJw09M9bfyHZE3o2fP3axfoCmPb148W0EKjd3/ta0C0IS6FSSAZjE0omQy
PFB5R2VyjR9/MSP0CbRu/kgku8yUzTA8XuJjUWwCT+JYxP7peOAIBoKFJpuHy4dq
5omfndXDKmVUzzWSUhPMIFrlk0QX/V7fC3LAMwtjuhdJ7KlrNVyYUuOpYgS0jTYQ
BpcoQFqXRmO2v1kO+A8KIO9+ZWDnOP9ma1YFbrHfPU9Px5j5OexDQ+nJ+2iLiHdo
DA9R5Sse+51/INk+4ZNZxO4BuoSNYz991KGUX/3w5EF7vsC1DX6Gf8E8HCMd2sYR
8S06Qm0=
-----END CERTIFICATE-----
        "
        );

        let intermediate = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIEOTCCAiGgAwIBAgIUR2Y0g1z8TPo2nJguc6VquNHd5QwwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPeDUwOS1saW1iby1yb290MCAXDTY5MTIzMTE5MDAwMFoY
DzI5NjkwNTAyMTkwMDAwWjAsMSowKAYDVQQDDCF4NTA5LWxpbWJvLWludGVybWVk
aWF0ZS1wYXRobGVuLTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCN
oX/AIxNzzgD9D9Jkyx0nj2bNPblIYkl3UZK9v8+oTAkDkkk9fwZJfrzgNk7DYZ7L
CN9urM5NmQkmEb0h4iBHwxZ2srfSX5Q2406FqZe/naDvPRS6SH06nYlEAyFM0AYq
hyfQq/eNpqHv+/2HPRYmoBAD0mnDPF50aI6p5EpLt+HRRp4aoJDZCLuat1YnEm4U
eEqRQPdJNjEAqU7rpoJ3I0tDQMg8VwZbtIQizfFAgq+iaoOVFtywCnD6C6GmLNXr
uFrBSii0GBk1Wj/ilORzE6y0CQQB+0b0pw1qXvWhnDh9KmIrUGng6rhEqn9M+ygB
G0OX+9bOrqe7DMG9wVKrAgMBAAGjYzBhMB0GA1UdDgQWBBQfIo3knL8JZy5RO/iJ
xGZD2WrLbTAfBgNVHSMEGDAWgBQk6STcTVDVaZDL0bPuPX6jOckpLTASBgNVHRMB
Af8ECDAGAQH/AgEAMAsGA1UdDwQEAwICBDANBgkqhkiG9w0BAQsFAAOCAgEA4KB4
ZLZsoKnY/bOKZmsT8hYVlzlFWCjitKt0wW5oQ888xB6mRuF7RN4UB4vS+wGsxD+U
Uruv0wfehEfuljN9N67pKpzE38ZzbvDuyhCHTGl/swLVlASWQPdPIG/fba/SFDqC
zvCQ2O1EZCNsixw2EVi6u/9CJQPmTab6kgQE0z6R1Xsd5Jr8FkG3funRtbeKAIyG
Gal8jBztw7ND06B+NlTSUK7S8nASK1FF8UXl9eDzkgc///NEF3BN4GWDE1wqv4KD
d3KAhCC3Jc8pjVnkKhLT5JHc7Xm4wI9NTM5Z6OU9dazUbg1ZPSxny8ZLym+6uTaz
wiDfWSDiuJFs7hvAeSZxJ9YAqqtATMaDaidSZGg3hFsXlrZ55J6MgxMw0J2Yelvv
/1dTUaNSH5E8o4y2EDZDY+F6w4qyrSv8Y/LGCjAqA+2KyZ5UYwTvAZBmW8aex1kc
t4nmFaYww8mXjV0BKT8IpocQwEg0nCTGFBcym+JQ5gsZDrVo5tpwFh0uDMnCp4ZW
9pvsY4dYKErjakjVxNfm3zucWb+i87m0N+XkosGshvZzCyiAJllZvIAz9rYGlgpL
lIxFcUftR94ANsows30zT+mkrh9YotLzKzTfL7QGd8+MIbahfasLY91UISP90ExR
iVjMQ19R8XwBE6n9t+BePjjvfF5ws+ahgpjx1AM=
-----END CERTIFICATE-----
        "
        );

        let store = Store::new([]);
        let ops = NullOps {};
        let time = asn1::DateTime::new(2023, 1, 1, 0, 0, 0).unwrap();
        let policy: Policy<'_, _> = Policy::new(ops, None, time);
        assert!(
            verify(&ee, [intermediate.clone()], &policy, &store)
                == Err(PolicyError::Other("chain construction exhausted all candidates").into())
        );
    }

    #[test]
    fn test_verify_pathlen_violated() {
        let ee = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIEaTCCAlGgAwIBAgIUcoYtjE7xI0Afx91WvWxcJAKYJRowDQYJKoZIhvcNAQEL
BQAwZzE5MDcGA1UECwwwMTA5MTQ2ODU3OTYwNzQyMDY3Nzk4MzI5NzE5Nzg1NDc2
ODM4MDMxMDA1Njk2Njg2MSowKAYDVQQDDCF4NTA5LWxpbWJvLWludGVybWVkaWF0
ZS1wYXRobGVuLTAwIBcNNjkxMjMxMTkwMDAwWhgPMjk2OTA1MDIxOTAwMDBaMBgx
FjAUBgNVBAMMDXg1MDktbGltYm8tZWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQCrozwOGLyFsGXZMx7GJxB+wSuyiNQqS23EYPci7ms63M8iyWBK+gq8
grziRLdchB+4ID70jz8ik3OZ3Fhew+RC3NV0wKbQSzqgoF+ym6/yN5PipSsJUrdJ
Coktb69R7F55jiVJF3GghyB20JQyAL7whXcUjzQ4VOLfwp2I5ioAnYCG/7NetCgP
CWXkseMGYfJRsvpIB/CXIMlwvTIMSR/kgfeeyScl5JGjMxRF6sih81JL2GIu6Sts
TVQIuYJXEtnJUmn8fRDItu44m+sGpmT2bnyEMUFmSLGyxALviayDhLFZFG3DKMwh
CoO9fWQBuie+rvrSMY6DIP5TQj4JIiZHAgMBAAGjWjBYMB0GA1UdDgQWBBSzKwH4
TC1o+Zwgh7TXbi4D3qnCnDAfBgNVHSMEGDAWgBSdZzog5CmYVJ0DfuO8DjLw5TAy
bzAJBgNVHRMEAjAAMAsGA1UdDwQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAmQhP
2EI0G3rGUy+kEmjd7eG+fZ4ChXFcGGCxcGs7ZUDg1/h2OkQU93CmzCTWCbOB6+7E
Ct2HqmdTJIngZJ9Irk3gJsJ28mBfKCJ7+W1Q/OuchPR0VDhUxpctWk01CMXLxi5F
bgjxvhMY/0PMUiGon7dj0+ZG847zQuZcoB3Ffa6UrRtPNzXFLlSW4YtqPd7MN+vc
SwiJMMXWtxYbavdUQStcQtFecF+GZ36sKqfiNkvOA4A+/piUIkfLK1gNEuzQM8qV
k91xfDoB+3OP+0I5b52aI7ia4PLnMBKdhPguBieLo09i1VavsLHS/3ouWOKdkDET
TzyWdowdzDGc9+cMABuQtRmnY+OwWRRfzWwLjSQAKqhxDsfpmanOhh058opyRfhY
1R60Jjzq0R5S+OKk1gh/ccZZPGgX1zB4jXp8bRugIJup2q3fqQzxAzcqAKScCclA
gd5BB+ouo7Q9I1uSeor/u/2q45wwPqJvDZIuUB9bPSq4ij4LOr2IlVYN16FvxXIQ
1Eazyv4c6kG/Aus+qp3yCex2xa0ds1eLby76l9d+PYobm7AQldciF1vmRjItHHaz
r/yKTsYRN9TmY2itfQROsUg5WmKRixFXAUyBmgb+FWftevQyMpZcT8bG6Hg/PaYN
0cC73F5qsc2+cRW1xdDl7xW+iPMKz/KmPnat7Jo=
-----END CERTIFICATE-----
            "
        );

        let ica1 = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIFdDCCA1ygAwIBAgIUEx5Qe1ttWaNTfPXCZa/SVBOBwq4wDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPeDUwOS1saW1iby1yb290MCAXDTY5MTIzMTE5MDAwMFoY
DzI5NjkwNTAyMTkwMDAwWjBnMTkwNwYDVQQLDDAyMDQ5MTQxOTI2OTEyODcwMjE1
NTE3NDU4NDQ3MzQ0NDc3NjIxNTIxOTE4MjMwNzcxKjAoBgNVBAMMIXg1MDktbGlt
Ym8taW50ZXJtZWRpYXRlLXBhdGhsZW4tMDCCAiIwDQYJKoZIhvcNAQEBBQADggIP
ADCCAgoCggIBALIF/FHh0En9tNBNGnS32DiksKh4aFhuypOqwMNs0S60DFFLVn53
pRbDT/evYCaKMR6dDQ83WpZkZFsmi+y4TeIr7Pcp573w5vjS+0nS2OXX0t3mOK+e
6x91RMnIuaH/getOBQ5+g46C+dauxVYh+NWM7XrHFJTvGZZpVl2yGkwES0SSN1Ru
9hkc7iWGch0Gn95cBILSQuZbMYfx4zVAhqnCLM4BnNPKXqpfV9Ikn/K2Ok7hpd0/
8dE3WsdxorqA/YTBLN4DoEqsLILgTl/HeI8+i6nfniC67JPfQBI09jetwy9IHDJl
Y6ZHiNYSR3BBKl9WDFcyfLTvy11Zi89fTvEge4eazlUl2K/q3pL775y2Ek0aCQ2f
3gXDoSfccJF/oBhgNCyZzWUW9Rq0FZtmxkQbJzGF51gRuiG/L1UaligPQQ47FtQE
Im0e8gV2BrL3USd/m0xsR0zSxZVZmQEQyrtod/WdUtOdx1BUE7QvXmWVp4+QB7hg
oMgOumReR13KQ8aXd1Bfj5OiBc1B9UaL2N7/PzquNpuLt8x+jjSuw67zZee5URuw
4zVx050j83f/qDjzKAwb1rcxdjUGvLVJVwAqcxiTHOH1nLlNVbK5u8sVQsnYDaB2
jT+RXKcsnY7tmN21x+T84GsFADNpAy2YoUlYeAqQ8NK0kVA/U8AJPQjfAgMBAAGj
YzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgIEMB8GA1UdIwQYMBaA
FNAxi7w73NS0/VlZibm1DltIotGEMB0GA1UdDgQWBBTrJrLI8aeMGxO0Tj6pD4B1
n2d4NDANBgkqhkiG9w0BAQsFAAOCAgEAeKKpKejROdi709D0INzcf1RtOlGcoxlh
oIbIRuYZraFJlsqQbSYbJvOPGumDwAqTibO//re796yu5nQme1YNPzNGxMJe/lm7
kUFcXO4/QIxXxh32/PSX2C/EEO3Yg2eBdnoqOC2qwAsJnP5NLV4usIE1V7w5mRx8
Ykunqi0hTAg2bUaPKfmgWa1B9d0VzAtSXyUFASYuiPTkqzyT17ehrLcXfbRoHUdz
xkt4GmLpf/0DsjPLjmnWxhuBYlEOiy+O0XHJBBmDJEQi26kahNqnspTCxJ0PRxza
jqZzwuTxi53PCAsJwY2ZiicWUPMJ3xHembjSZZkuU9hcb1aixkbkSnE7JtleCCHt
Txbim0s8IpExpqo/25oBLsX1VTwGl2kpzClVzc+zY0jLLrbhg1LRz0ZNQvWov3cm
a8jjOBvaR1BZ0/yvk6wxpInESuGkAtCoNeJCqipA88LKT2KY1QzgxEbN7um+StWS
xGoCyOvujQfc3/wjaUmiMY2+wt5DCSHKALA88yzU12iL8b6crPK3V3UUcKUwbocg
bEb5VT5KwAotK1cpdc4agZCnrUCVS7kBUufKHYPwseT5gAFLXEYK8UoS0WTCVn8z
tTZE2qAbb7TJzjcnpSw6PzU2xPEFVtbsVE7YcRkYtbhRLV32dHrnhOYSjwHPfr4y
NSqd4SA0rBE=
-----END CERTIFICATE-----
        "
        );

        let ica2 = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIFwTCCA6mgAwIBAgIUcmzLOEoPYUSPHc9kvZxdQY9aJdowDQYJKoZIhvcNAQEL
BQAwZzE5MDcGA1UECwwwMjA0OTE0MTkyNjkxMjg3MDIxNTUxNzQ1ODQ0NzM0NDQ3
NzYyMTUyMTkxODIzMDc3MSowKAYDVQQDDCF4NTA5LWxpbWJvLWludGVybWVkaWF0
ZS1wYXRobGVuLTAwIBcNNjkxMjMxMTkwMDAwWhgPMjk2OTA1MDIxOTAwMDBaMGcx
OTA3BgNVBAsMMDEwOTE0Njg1Nzk2MDc0MjA2Nzc5ODMyOTcxOTc4NTQ3NjgzODAz
MTAwNTY5NjY4NjEqMCgGA1UEAwwheDUwOS1saW1iby1pbnRlcm1lZGlhdGUtcGF0
aGxlbi0wMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy8cq9B1+iaEJ
oOs/rcgWYpJMUY8bM+spsl6Pn8WeZhPKCW5naM+H6pvmBLg5Zeeld3goo30RqO4F
yRsOXVPXoJPqJWJFC5d8MRKJb1YEwuCUU9cKcSuQiln4HUBYPW5bqkCE/JhfohXI
dc9H1o6zeyyj7lgrKBVQmeObOj/XmAF2GNdWH2bIh1RBl4A/1CxXwml4Kog7TzXD
qx/d1Kloa89cmaj5H5drIgCy0aRNwRy9RHWE76Pcb8SjqITWPHONA+gelANoglfq
iFPZ51opTKi6OvvCptsgSRYPBHak6FQG9jPj7BF/YiRulyQYMBKkGISNExILtsre
a1a+dytNOa4VlsIAraGw4YdIhKgM4hbilE6q69cUeojeVW3C6TvlR158KC1Rsv7P
VY7K2ZGW0eIUWKr/32tWOJMNBOalZwMGTBxyoJEWIINyskEU0xvLI5pdWjWHixsG
7fxUvKDtsCeE+dpATSP81AaxUA1BtTh51oQVOd4XQJnkpBV789Fg5BlF5Bx7PpHl
vhqUmLcOWtrBIR40BxYIUiCvcR4ettqguuY4SucYCAlJw7UoMxx1yNz4jfE4bJY5
+I6qyZXsQtlBo6WgQbXLI3dt1sWR+yrUDYIrlFpWrYDwfzpFav2nMfj7Pku0tzF0
KLgpE7yXaZxH2fhBhC7XcdEZMGsp3w8CAwEAAaNjMGEwEgYDVR0TAQH/BAgwBgEB
/wIBADALBgNVHQ8EBAMCAgQwHwYDVR0jBBgwFoAU6yayyPGnjBsTtE4+qQ+AdZ9n
eDQwHQYDVR0OBBYEFJ1nOiDkKZhUnQN+47wOMvDlMDJvMA0GCSqGSIb3DQEBCwUA
A4ICAQB4UMVhJdP000QgoUj8Z0bZx//6HEH2nAXPRNFwmzOFUjXS+qb0lMwrhXOy
BVIHWuGPUDZy+qVXnw7nVt9sfPFGUjgXQ4jNWOm2lQsfJ6LP1j4Gj0+SzKfz8MgH
i1gYCZeejJ5h2yhAyfZ39i8arJmIeToPIn+Lesp/53cAexTlCwszgR37yWaG+5UU
AeCA+7pcqx0Qm5BgoEUOLikUT8GfwX9C3E084UjUrgy6vJN+Bx76TFqahQA/ErSy
11Ek431nkGOIDc33rpfs/AYSTShsSlB8xu328Pmn20p1REbpcJDPmDE5dLNd5S/u
pgLMWo9bbLE6qsi5BBOyVuzCzihN9CmSPfux1jTAGMKsVHeRiN+9nCWFxL786Rzy
IptR/SEuLiBB6DUJVXAPNuSRUWkEX94vPIy0vTlOaDcmSy9X5XE47MKBo9Ct/c5o
Qn4edY6URTSV6regYIfGfK9IioLZwI7j/AMbldscQ92tB9HsKGzZYTD47kr7c7IL
RwCibhrqroUllMCQ109R1KtyBDgNedHFQ7wWDj8ESGJFiEgO4RwU8a+trf+Ky+He
+CHtXoZcy/ROaeqaRCvDG9253IFxi0/3zUHf9TFT+FvmgcVwXi9jNdEDpncKZ+Vw
TqGoQg2eW2AXbkZ+XrIgt+oKwFZndF05kAMeDTxTyOv2kQH/fA==
-----END CERTIFICATE-----
            "
        );

        let root = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIFAzCCAuugAwIBAgIUI+SrkcegkxHgRJZ21QU8ACJ6DOUwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPeDUwOS1saW1iby1yb290MCAXDTY5MTIzMTE5MDAwMFoY
DzI5NjkwNTAyMTkwMDAwWjAaMRgwFgYDVQQDDA94NTA5LWxpbWJvLXJvb3QwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC8y9k0m4pz4olDu9ec65yjJLci
RaQS81pkY2h8SxLhTFTtloAG1QszR3xHOyfN8dKyXd7DMjKHZAy019TmuDxHyVqv
CxhoDX6qVLHcGVhSajgAYnPxJ0DlTMjhNK1sDv0xgokGj9SsbA6E2NMgF0hVqSP1
fM/IsCo6NYJLZREki4vGJ/Wejv6krT7sNPqICRSJXJB/L9NYNZTSjo4Ju5cdEVuA
r6X0O0r3T4FZUDV68ft7qHJl0iV+u1ScTh8SmKQwVKdH5k4+g5ZNeFRqe07rm6Y9
owWxVfb1+cm5crHGGKxqtBmj2YHj4nhQlLHxzfylMKN4rw8DN2PUQ8Mf7tkoN3kc
S4QkgLMwRWdbIrRlluZQAt9SWg2dbi0M39iXQQZD+pu9GoHcckOgMm+rVQrfn+W9
+njiB74S8QKkZCoCU6WRpU+sSiNUTZwCO8E4pTPzpMMbYm95GQbRchZdnu5t2ABR
TpMPLiLIp09bcAq0ZtNvoQ1Qa4NQ1opJaZvph/EseubZ5QPP/4zABu6zb/kZn53b
l7R+ykMTNgXw2lWLGqAOzsqid5Aidp3dVZhelSaQ7XBaMU9vTAlktD+EYUowNJgR
TROMOcYsmnxqatwoQwgi+lXArL7wRcU6Kv6Ex8IlpwlzirC3za7uh2Pg4aKXsxZc
kcJiaR+q81XPcJarrwIDAQABoz8wPTAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQE
AwICBDAdBgNVHQ4EFgQU0DGLvDvc1LT9WVmJubUOW0ii0YQwDQYJKoZIhvcNAQEL
BQADggIBACmN5xJFpIFxP9meIa9DEncT931WL3poaPJn7yDKu5a8kJfmphVJU0KT
DOlAxLqeg4C3r/9733UHJQveAi+Mdns8O7ibBML8ge3pYEfccG/Naj4PyMbTLCHa
VLAzii2yXrUA+snNkJDuXuGQ9jSzJhan4E+ujZRt74Pt0vIR592/Jwa6CsPtlUXm
XVVwlXtah9dVwRcGHY8NyE1j01PlGtou7qcVaMWPcoKpWJEOb/IMz2zuq4u1bteE
WPEEwoc4z1DNoAXJVmew0h4NfDQem0qf21AyKx0VOybKYj+sM1rca3DhVh6doY95
9FhQzMTIeTyF0Ha409mI01Uo21Mw2K3CuRMBFFzHqiQp/FtDOghk3DPwe4Uj3Yv7
Y7C/lmEavH6eaaUoXHTlvsFjYGjnuV2eT4YYm0kvhJNp5YYxJxjXTV8mVYTy4Wd9
yLO64Q84KAFCZfYJLXpaGZXe7H5Ki1iNabRJr7YldXGY0BPQ6GCwFB/eIgEOIrqb
wlQr0hCXx0OC3uts94nuOCpra86EaQs/qzJ1yMLxpUEN3JP8lBaj/uRXNhqC8R5+
dw/3BAjyHf+7GbtUY+tWIU2voxs1PWQpkU8BSnXlkBBT5OwIM6gq7FrAEs020/EA
CPz+qQOJcoMt8w6dIMgADFNgoigKtKM1rX7D0UuuOUVYNfq9ERVf
-----END CERTIFICATE-----
            "
        );

        let store = Store::new([root]);
        let ops = NullOps {};
        let time = asn1::DateTime::new(2023, 1, 1, 0, 0, 0).unwrap();
        let policy: Policy<'_, _> = Policy::new(ops, None, time);
        assert!(
            verify(&ee, [ica1.clone(), ica2.clone()], &policy, &store)
                == Err(PolicyError::Other("chain construction exhausted all candidates").into())
        );
    }
}
