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

from __future__ import absolute_import, division, print_function

import inspect
import sys


DeprecatedIn06 = DeprecationWarning


def register_interface(iface):
    def register_decorator(klass):
        iface.register(klass)
        return klass
    return register_decorator


class InterfaceNotImplemented(Exception):
    pass


def verify_interface(iface, klass):
    for method in iface.__abstractmethods__:
        if not hasattr(klass, method):
            raise InterfaceNotImplemented(
                "{0} is missing a {1!r} method".format(klass, method)
            )
        spec = getattr(iface, method)
        actual = getattr(klass, method)
        if inspect.getargspec(spec) != inspect.getargspec(actual):
            raise InterfaceNotImplemented(
                "{0}.{1}'s signature differs from the expected".format(
                    klass, method
                )
            )


def bit_length(x):
    if sys.version_info >= (2, 7):
        return x.bit_length()
    else:
        return len(bin(x)) - (2 + (x <= 0))
