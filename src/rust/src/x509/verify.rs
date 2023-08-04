// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.pub(crate) struct PyCryptoOps {}

use cryptography_x509::certificate::Certificate;
use cryptography_x509_validation::ops::CryptoOps;

use crate::error::CryptographyResult;

use super::sign;

pub(crate) struct PyCryptoOps {}

impl CryptoOps for PyCryptoOps {
    type Key = pyo3::Py<pyo3::PyAny>;

    fn public_key(&self, cert: &Certificate<'_>) -> Option<Self::Key> {
        pyo3::Python::with_gil(|py| -> Option<Self::Key> {
            // This makes an unnecessary copy. It'd be nice to get rid of it.
            let spki_der =
                pyo3::types::PyBytes::new(py, &asn1::write_single(&cert.tbs_cert.spki).ok()?);
            Some(
                py.import(pyo3::intern!(
                    py,
                    "cryptography.hazmat.primitives.serialization"
                ))
                .ok()?
                .getattr(pyo3::intern!(py, "load_der_public_key"))
                .ok()?
                .call1((spki_der,))
                .ok()?
                .into(),
            )
        })
    }

    fn is_signed_by(&self, cert: &Certificate<'_>, key: Self::Key) -> bool {
        pyo3::Python::with_gil(|py| -> CryptographyResult<()> {
            sign::verify_signature_with_signature_algorithm(
                py,
                key.as_ref(py),
                &cert.signature_alg,
                cert.signature.as_bytes(),
                &asn1::write_single(&cert.tbs_cert)?,
            )
        })
        .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use cryptography_x509::certificate::Certificate;
    use cryptography_x509_validation::ops::CryptoOps;

    use super::PyCryptoOps;

    #[test]
    fn test_pycryptoops() {
        let pem = "
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
        ";
        let der = pem::parse(pem).unwrap();
        let cert = asn1::parse_single::<Certificate<'_>>(der.contents()).unwrap();

        let ops = PyCryptoOps {};
        let pk = ops.public_key(&cert);

        assert!(pk.is_some());
        assert!(ops.is_signed_by(&cert, pk.unwrap()));
    }
}
