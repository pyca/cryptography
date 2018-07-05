# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest


def pytest_addoption(parser):
    parser.addoption("--wycheproof-root", default=None)


@pytest.fixture
def whycheproof(request):
    wycheproof = request.config.getoption("--wycheproof-root")
    if wycheproof is None:
        pytest.skip("--wycheproof-root not provided")
    return wycheproof

