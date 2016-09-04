# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import abc

import pytest

import six

from cryptography.utils import (
    InterfaceNotImplemented, register_interface_if, verify_interface
)


def test_register_interface_if_true():
    @six.add_metaclass(abc.ABCMeta)
    class SimpleInterface(object):
        pass

    @register_interface_if(1 == 1, SimpleInterface)
    class SimpleClass(object):
        pass

    assert issubclass(SimpleClass, SimpleInterface) is True


def test_register_interface_if_false():
    @six.add_metaclass(abc.ABCMeta)
    class SimpleInterface(object):
        pass

    @register_interface_if(1 == 2, SimpleInterface)
    class SimpleClass(object):
        pass

    assert issubclass(SimpleClass, SimpleInterface) is False


class TestVerifyInterface(object):
    def test_verify_missing_method(self):
        @six.add_metaclass(abc.ABCMeta)
        class SimpleInterface(object):
            @abc.abstractmethod
            def method(self):
                """A simple method"""

        class NonImplementer(object):
            pass

        with pytest.raises(InterfaceNotImplemented):
            verify_interface(SimpleInterface, NonImplementer)

    def test_different_arguments(self):
        @six.add_metaclass(abc.ABCMeta)
        class SimpleInterface(object):
            @abc.abstractmethod
            def method(self, a):
                """Method with one argument"""

        class NonImplementer(object):
            def method(self):
                """Method with no arguments"""

        # Invoke this to ensure the line is covered
        NonImplementer().method()
        with pytest.raises(InterfaceNotImplemented):
            verify_interface(SimpleInterface, NonImplementer)

    def test_handles_abstract_property(self):
        @six.add_metaclass(abc.ABCMeta)
        class SimpleInterface(object):
            @abc.abstractproperty
            def property(self):
                """An abstract property"""

        class NonImplementer(object):
            @property
            def property(self):
                """A concrete property"""

        # Invoke this to ensure the line is covered
        NonImplementer().property
        verify_interface(SimpleInterface, NonImplementer)
