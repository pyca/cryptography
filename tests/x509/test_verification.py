# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import os
from ipaddress import IPv4Address

import pytest

from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.general_name import DNSName, IPAddress
from cryptography.x509.verification import (
    PolicyBuilder,
    Store,
    verify,
)
from tests.x509.test_x509 import _load_cert


def test_verify_basic():
    ee = load_pem_x509_certificate(
        b"""
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
"""
    )

    intermediate = load_pem_x509_certificate(
        b"""
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
"""
    )

    root = load_pem_x509_certificate(
        b"""
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
"""
    )

    policy = PolicyBuilder().build_server_verifier()
    store = Store([root])
    chain = verify(ee, policy, [intermediate], store)

    assert chain == [ee, intermediate, root]


class TestPolicyBuilder:
    def test_time_already_set(self):
        with pytest.raises(ValueError):
            PolicyBuilder().time(datetime.datetime.now()).time(
                datetime.datetime.now()
            )

    def test_ipaddress_subject(self):
        policy = PolicyBuilder().build_server_verifier(
            IPAddress(IPv4Address("0.0.0.0"))
        )
        assert policy.subject == IPAddress(IPv4Address("0.0.0.0"))

    def test_dnsname_subject(self):
        policy = PolicyBuilder().build_server_verifier(
            DNSName("cryptography.io")
        )
        assert policy.subject == DNSName("cryptography.io")

    def test_subject_bad_types(self):
        # Subject must be a supported GeneralName type
        with pytest.raises(TypeError):
            PolicyBuilder().build_server_verifier(
                "cryptography.io"  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().build_server_verifier(
                "0.0.0.0"  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().build_server_verifier(
                IPv4Address("0.0.0.0")  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().build_server_verifier(
                None  # type: ignore[arg-type]
            )

    def test_builder_pattern(self):
        now = datetime.datetime.now().replace(microsecond=0)

        builder = PolicyBuilder()
        builder = builder.time(now)

        verifier = builder.build_server_verifier(DNSName("cryptography.io"))
        assert verifier.subject == DNSName("cryptography.io")
        assert verifier.validation_time == now


class TestStore:
    def test_store_rejects_empty_list(self):
        with pytest.raises(ValueError):
            Store([])

    def test_store_rejects_non_certificates(self):
        with pytest.raises(TypeError):
            Store(["not a cert"])  # type: ignore[list-item]

    def test_store_initializes(self):
        cert = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
        )
        assert Store([cert]) is not None
