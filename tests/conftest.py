# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import pytest

from cryptography.hazmat.backends.openssl import backend as openssl_backend

from .utils import check_backend_support


def pytest_report_header(config):
    # Performed in this function to enable it before any test collection
    # and before the information about FIPS is printed
    if config.getoption("--enable-fips"):
        enable_fips()

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
    return openssl_backend


@pytest.fixture
def disable_rsa_checks(backend):
    # Use this fixture to skip RSA key checks in tests that need the
    # performance.
    backend._rsa_skip_check_key = True
    yield
    backend._rsa_skip_check_key = False


def enable_fips():
    openssl_backend._lib._base_provider = (
        openssl_backend._lib.OSSL_PROVIDER_load(
            openssl_backend._ffi.NULL, b"base"
        )
    )
    openssl_backend.openssl_assert(
        openssl_backend._lib._base_provider != openssl_backend._ffi.NULL
    )
    openssl_backend._lib._fips_provider = (
        openssl_backend._lib.OSSL_PROVIDER_load(
            openssl_backend._ffi.NULL, b"fips"
        )
    )
    openssl_backend.openssl_assert(
        openssl_backend._lib._fips_provider != openssl_backend._ffi.NULL
    )

    res = openssl_backend._lib.EVP_default_properties_enable_fips(
        openssl_backend._ffi.NULL, 1
    )
    openssl_backend.openssl_assert(res == 1)
    assert openssl_backend._is_fips_enabled()
    openssl_backend._fips_enabled = openssl_backend._is_fips_enabled()
