# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import abc

from cryptography.utils import verify_interface


class TestVerifyInterface:
    def test_noop(self):
        class SimpleInterface(metaclass=abc.ABCMeta):
            @abc.abstractmethod
            def method(self):
                """A simple method"""

        class NonImplementer:
            pass

        verify_interface(SimpleInterface, NonImplementer)
