# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.hazmat.backends import _available_backends

from .utils import check_backend_support, select_backends, skip_if_empty


def pytest_generate_tests(metafunc):
    if "backend" in metafunc.fixturenames:
        names = metafunc.config.getoption("--backend")
        selected_backends = select_backends(names, _available_backends())

        filtered_backends = []
        required = metafunc.function.requires_backend_interface
        required_interfaces = [
            mark.kwargs["interface"] for mark in required
        ]
        for backend in selected_backends:
            if all(
                isinstance(backend, iface) for iface in required_interfaces
            ):
                filtered_backends.append(backend)

        # If you pass an empty list to parametrize Bad Things(tm) happen
        # as of pytest 2.6.4 when the test also has a parametrize decorator
        skip_if_empty(filtered_backends, required_interfaces)

        metafunc.parametrize("backend", filtered_backends)


@pytest.mark.trylast
def pytest_runtest_setup(item):
    check_backend_support(item)


def pytest_addoption(parser):
    parser.addoption(
        "--backend", action="store", metavar="NAME",
        help="Only run tests matching the backend NAME."
    )
