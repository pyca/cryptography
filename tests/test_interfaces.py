# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import abc

import pytest

from cryptography.utils import (
    InterfaceNotImplemented,
    register_interface_if,
    verify_interface,
)


def test_register_interface_if_true():
    class SimpleInterface(metaclass=abc.ABCMeta):
        pass

    @register_interface_if(1 == 1, SimpleInterface)
    class SimpleClass(object):
        pass

    assert issubclass(SimpleClass, SimpleInterface) is True


def test_register_interface_if_false():
    class SimpleInterface(metaclass=abc.ABCMeta):
        pass

    @register_interface_if(1 == 2, SimpleInterface)
    class SimpleClass(object):
        pass

    assert issubclass(SimpleClass, SimpleInterface) is False


class TestVerifyInterface(object):
    def test_verify_missing_method(self):
        class SimpleInterface(metaclass=abc.ABCMeta):
            @abc.abstractmethod
            def method(self):
                """A simple method"""

        class NonImplementer(object):
            pass

        with pytest.raises(InterfaceNotImplemented):
            verify_interface(SimpleInterface, NonImplementer)

    def test_different_arguments(self):
        class SimpleInterface(metaclass=abc.ABCMeta):
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
        class SimpleInterface(metaclass=abc.ABCMeta):
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

    def test_signature_mismatch(self):
        class SimpleInterface(metaclass=abc.ABCMeta):
            @abc.abstractmethod
            def method(self, other: object) -> int:
                """Method with signature"""

        class ClassWithoutSignature:
            def method(self, other):
                """Method without signature"""

        class ClassWithSignature:
            def method(self, other: object) -> int:
                """Method with signature"""

        verify_interface(SimpleInterface, ClassWithoutSignature)
        verify_interface(SimpleInterface, ClassWithSignature)
        with pytest.raises(InterfaceNotImplemented):
            verify_interface(
                SimpleInterface, ClassWithoutSignature, check_annotations=True
            )
        verify_interface(
            SimpleInterface, ClassWithSignature, check_annotations=True
        )
