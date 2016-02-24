# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function


# This has to happen in a top level conftest.py because otherwise it won't be
# executed by pytest early enough for this option to be added to the binary and
# it be available for passing into py.test. Everything else can still go into
# cryptography/tests/conftest.py as it always has.
def pytest_addoption(parser):
    parser.addoption(
        "--backend", action="store", metavar="NAME",
        help="Only run tests matching the backend NAME."
    )
