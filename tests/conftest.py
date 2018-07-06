# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.hazmat.backends.openssl import backend as openssl_backend

from .utils import check_backend_support, load_wycheproof_tests


def pytest_report_header(config):
    return "OpenSSL: {0}".format(openssl_backend.openssl_version_text())


def pytest_addoption(parser):
    parser.addoption("--wycheproof-root", default=None)


class WycheproofTest(object):
    def __init__(self, testgroup, testcase):
        self.testgroup = testgroup
        self.testcase = testcase


@pytest.fixture
def wycheproof(request):
    wycheproof = request.config.getoption("--wycheproof-root")
    if wycheproof is None:
        pytest.skip("--wycheproof-root not provided")

    paths = request.node.get_marker("wycheproof_tests").args
    for path in paths:
        for testgroup, testcase in load_wycheproof_tests(wycheproof, path):
            yield WycheproofTest(testgroup, testcase)


@pytest.fixture()
def backend(request):
    required_interfaces = [
        mark.kwargs["interface"]
        for mark in request.node.get_marker("requires_backend_interface")
    ]
    if not all(
        isinstance(openssl_backend, iface) for iface in required_interfaces
    ):
        pytest.skip(
            "OpenSSL doesn't implement required interfaces: {0}".format(
                required_interfaces
            )
        )

    check_backend_support(openssl_backend, request)
    return openssl_backend
