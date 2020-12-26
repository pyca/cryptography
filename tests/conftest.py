# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import pytest

from cryptography.hazmat.backends.openssl import backend as openssl_backend

from .utils import check_backend_support


def pytest_report_header(config):
    return "\n".join(
        [
            "OpenSSL: {}".format(openssl_backend.openssl_version_text()),
            "FIPS Enabled: {}".format(openssl_backend._fips_enabled),
        ]
    )


def pytest_addoption(parser):
    parser.addoption("--wycheproof-root", default=None)


def pytest_runtest_setup(item):
    if openssl_backend._fips_enabled:
        for marker in item.iter_markers(name="skip_fips"):
            pytest.skip(marker.kwargs["reason"])


@pytest.fixture()
def backend(request):
    required_interfaces = [
        mark.kwargs["interface"]
        for mark in request.node.iter_markers("requires_backend_interface")
    ]
    if not all(
        isinstance(openssl_backend, iface) for iface in required_interfaces
    ):
        pytest.skip(
            "OpenSSL doesn't implement required interfaces: {}".format(
                required_interfaces
            )
        )

    check_backend_support(openssl_backend, request)
    return openssl_backend
