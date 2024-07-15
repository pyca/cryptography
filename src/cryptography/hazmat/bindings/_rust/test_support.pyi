# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

class TestCertificate:
    not_after_tag: int
    not_before_tag: int
    issuer_value_tags: list[int]
    subject_value_tags: list[int]

def test_parse_certificate(data: bytes) -> TestCertificate: ...
