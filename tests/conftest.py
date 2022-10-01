# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import pytest

from cryptography.hazmat.backends.openssl import backend as openssl_backend

from .utils import check_backend_support


def pytest_configure(config):
    if config.getoption("--enable-fips"):
        openssl_backend._enable_fips()


def pytest_report_header(config):
    return "\n".join(
        [
            "OpenSSL: {}".format(openssl_backend.openssl_version_text()),
            "FIPS Enabled: {}".format(openssl_backend._fips_enabled),
        ]
    )


def pytest_addoption(parser):
    parser.addoption("--wycheproof-root", default=None)
    parser.addoption("--enable-fips", default=False)


def pytest_runtest_setup(item):
    if openssl_backend._fips_enabled:
        for marker in item.iter_markers(name="skip_fips"):
            pytest.skip(marker.kwargs["reason"])


@pytest.fixture()
def backend(request):
    check_backend_support(openssl_backend, request)

    # Ensure the error stack is clear before the test
    errors = openssl_backend._consume_errors_with_text()
    assert not errors
    yield openssl_backend
    # Ensure the error stack is clear after the test
    errors = openssl_backend._consume_errors_with_text()
    assert not errors
