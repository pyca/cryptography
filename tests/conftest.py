# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import sys

import pytest

from cryptography.hazmat.backends.openssl import backend as openssl_backend

from .utils import check_backend_support


def pytest_configure(config):
    if config.getoption("--enable-fips"):
        openssl_backend._enable_fips()


def pytest_report_header(config):
    return "\n".join(
        [
            f"OpenSSL: {openssl_backend.openssl_version_text()}",
            f"FIPS Enabled: {openssl_backend._fips_enabled}",
        ]
    )


def pytest_addoption(parser):
    parser.addoption("--wycheproof-root", default=None)
    parser.addoption("--enable-fips", default=False)
    # REMOVE ME WHEN WE DROP PYTHON 3.6 SUPPORT
    # This just adds a no-op flag so that we don't error on py36 where
    # pytest-subtests is stuck on 0.8.0
    if sys.version_info[:2] == (3, 6):
        parser.addoption("--no-subtests-shortletter", action="store_true")


def pytest_runtest_setup(item):
    if openssl_backend._fips_enabled:
        for marker in item.iter_markers(name="skip_fips"):
            pytest.skip(marker.kwargs["reason"])


@pytest.fixture()
def backend(request):
    check_backend_support(openssl_backend, request)

    # Ensure the error stack is clear before the test
    errors = openssl_backend._consume_errors()
    assert not errors
    yield openssl_backend
    # Ensure the error stack is clear after the test
    errors = openssl_backend._consume_errors()
    assert not errors
