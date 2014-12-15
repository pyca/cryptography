# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc
import inspect
import sys


DeprecatedIn06 = DeprecationWarning


def register_interface(iface):
    def register_decorator(klass):
        verify_interface(iface, klass)
        iface.register(klass)
        return klass
    return register_decorator


def read_only_property(name):
    return property(lambda self: getattr(self, name))


class InterfaceNotImplemented(Exception):
    pass


def verify_interface(iface, klass):
    for method in iface.__abstractmethods__:
        if not hasattr(klass, method):
            raise InterfaceNotImplemented(
                "{0} is missing a {1!r} method".format(klass, method)
            )
        if isinstance(getattr(iface, method), abc.abstractproperty):
            # Can't properly verify these yet.
            continue
        spec = inspect.getargspec(getattr(iface, method))
        actual = inspect.getargspec(getattr(klass, method))
        if spec != actual:
            raise InterfaceNotImplemented(
                "{0}.{1}'s signature differs from the expected. Expected: "
                "{2!r}. Received: {3!r}".format(
                    klass, method, spec, actual
                )
            )


if sys.version_info >= (2, 7):
    def bit_length(x):
        return x.bit_length()
else:
    def bit_length(x):
        return len(bin(x)) - (2 + (x <= 0))
