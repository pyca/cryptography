# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import six

from cryptography import utils
from cryptography.hazmat.primitives import interfaces


@utils.register_interface(interfaces.EllipticCurve)
class SECT571R1(object):
    name = "sect571r1"
    key_size = 571


@utils.register_interface(interfaces.EllipticCurve)
class SECT409R1(object):
    name = "sect409r1"
    key_size = 409


@utils.register_interface(interfaces.EllipticCurve)
class SECT283R1(object):
    name = "sect283r1"
    key_size = 283


@utils.register_interface(interfaces.EllipticCurve)
class SECT233R1(object):
    name = "sect233r1"
    key_size = 233


@utils.register_interface(interfaces.EllipticCurve)
class SECT163R2(object):
    name = "sect163r2"
    key_size = 163


@utils.register_interface(interfaces.EllipticCurve)
class SECT571K1(object):
    name = "sect571k1"
    key_size = 571


@utils.register_interface(interfaces.EllipticCurve)
class SECT409K1(object):
    name = "sect409k1"
    key_size = 409


@utils.register_interface(interfaces.EllipticCurve)
class SECT283K1(object):
    name = "sect283k1"
    key_size = 283


@utils.register_interface(interfaces.EllipticCurve)
class SECT233K1(object):
    name = "sect233k1"
    key_size = 233


@utils.register_interface(interfaces.EllipticCurve)
class SECT163K1(object):
    name = "sect163k1"
    key_size = 163


@utils.register_interface(interfaces.EllipticCurve)
class SECP521R1(object):
    name = "secp521r1"
    key_size = 521


@utils.register_interface(interfaces.EllipticCurve)
class SECP384R1(object):
    name = "secp384r1"
    key_size = 384


@utils.register_interface(interfaces.EllipticCurve)
class SECP256R1(object):
    name = "secp256r1"
    key_size = 256


@utils.register_interface(interfaces.EllipticCurve)
class SECP224R1(object):
    name = "secp224r1"
    key_size = 224


@utils.register_interface(interfaces.EllipticCurve)
class SECP192R1(object):
    name = "secp192r1"
    key_size = 192


_CURVE_TYPES = {
    "prime192v1": SECP192R1,
    "prime256v1": SECP256R1,

    "secp192r1": SECP192R1,
    "secp224r1": SECP224R1,
    "secp256r1": SECP256R1,
    "secp384r1": SECP384R1,
    "secp521r1": SECP521R1,

    "sect163k1": SECT163K1,
    "sect233k1": SECT233K1,
    "sect283k1": SECT283K1,
    "sect409k1": SECT409K1,
    "sect571k1": SECT571K1,

    "sect163r2": SECT163R2,
    "sect233r1": SECT233R1,
    "sect283r1": SECT283R1,
    "sect409r1": SECT409R1,
    "sect571r1": SECT571R1,
}


@utils.register_interface(interfaces.EllipticCurveSignatureAlgorithm)
class ECDSA(object):
    def __init__(self, algorithm):
        self._algorithm = algorithm

    algorithm = utils.read_only_property("_algorithm")


def generate_private_key(curve, backend):
    return backend.generate_elliptic_curve_private_key(curve)


class EllipticCurvePublicNumbers(object):
    def __init__(self, x, y, curve):
        if (
            not isinstance(x, six.integer_types) or
            not isinstance(y, six.integer_types)
        ):
            raise TypeError("x and y must be integers.")

        if not isinstance(curve, interfaces.EllipticCurve):
            raise TypeError("curve must provide the EllipticCurve interface.")

        self._y = y
        self._x = x
        self._curve = curve

    def public_key(self, backend):
        try:
            return backend.load_elliptic_curve_public_numbers(self)
        except AttributeError:
            return backend.elliptic_curve_public_key_from_numbers(self)

    curve = utils.read_only_property("_curve")
    x = utils.read_only_property("_x")
    y = utils.read_only_property("_y")


class EllipticCurvePrivateNumbers(object):
    def __init__(self, private_value, public_numbers):
        if not isinstance(private_value, six.integer_types):
            raise TypeError("private_value must be an integer.")

        if not isinstance(public_numbers, EllipticCurvePublicNumbers):
            raise TypeError(
                "public_numbers must be an EllipticCurvePublicNumbers "
                "instance."
            )

        self._private_value = private_value
        self._public_numbers = public_numbers

    def private_key(self, backend):
        try:
            return backend.load_elliptic_curve_private_numbers(self)
        except AttributeError:
            return backend.elliptic_curve_private_key_from_numbers(self)

    private_value = utils.read_only_property("_private_value")
    public_numbers = utils.read_only_property("_public_numbers")
