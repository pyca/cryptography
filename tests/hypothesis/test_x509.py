# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from hypothesis import HealthCheck, example, given, settings
from hypothesis.strategies import text

from cryptography import x509


@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(text())
@example("CN=cryptography.io")
def test_name_from_rfc4514(data):
    # Check that if something parses then it round trips.
    try:
        name = x509.Name.from_rfc4514_string(data)
    except ValueError:
        return

    assert name.rfc4514_string() == data
