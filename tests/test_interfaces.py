# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc

import pytest

import six

from cryptography.utils import (
    InterfaceNotImplemented, register_interface, verify_interface
)


class TestVerifyInterface(object):
    def test_verify_missing_method(self):
        @six.add_metaclass(abc.ABCMeta)
        class SimpleInterface(object):
            @abc.abstractmethod
            def method(self):
                pass

        @register_interface(SimpleInterface)
        class NonImplementer(object):
            pass

        with pytest.raises(InterfaceNotImplemented):
            verify_interface(SimpleInterface, NonImplementer)

    def test_different_arguments(self):
        @six.add_metaclass(abc.ABCMeta)
        class SimpleInterface(object):
            @abc.abstractmethod
            def method(self, a):
                pass

        @register_interface(SimpleInterface)
        class NonImplementer(object):
            def method(self):
                pass

        with pytest.raises(InterfaceNotImplemented):
            verify_interface(SimpleInterface, NonImplementer)
