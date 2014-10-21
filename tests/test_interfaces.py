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
