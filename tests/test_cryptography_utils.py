# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import enum

from cryptography import utils


def test_enum():
    class TestEnum(utils.Enum):
        something = "something"

    assert issubclass(TestEnum, enum.Enum)
    assert isinstance(TestEnum.something, enum.Enum)
    assert repr(TestEnum.something) == "<TestEnum.something: 'something'>"
    assert str(TestEnum.something) == "TestEnum.something"
