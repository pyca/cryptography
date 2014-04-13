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

import six

from cryptography import utils
from cryptography.hazmat.primitives import interfaces


@utils.register_interface(interfaces.EllipticCurve)
class EllipticCurve(object):
    def __init__(self, name, key_size):
        self._name = name
        self._key_size = key_size

    @property
    def name(self):
        return self._name

    @property
    def key_size(self):
        return self._key_size


secp256k1 = EllipticCurve("secp256k1", 256)


@utils.register_interface(interfaces.EllipticCurvePublicKey)
class EllipticCurvePublicKey(object):
    def __init__(self, x, y, curve):
        if (
            not isinstance(x, six.integer_types) or
            not isinstance(y, six.integer_types)
        ):
            raise TypeError("private_key, x and y must be integers.")

        if not isinstance(curve, interfaces.EllipticCurve):
            raise TypeError("curve must provide the EllipticCurve interface.")

        self._y = y
        self._x = x
        self._curve = curve

    def verifier(self, signature, algorithm, backend):
        return backend.create_ecdsa_verification_ctx(self, signature, algorithm)

    @property
    def key_size(self):
        return self._curve.key_size

    @property
    def x(self):
        return self._x

    @property
    def y(self):
        return self._y

    @property
    def curve(self):
        return self._curve


@utils.register_interface(interfaces.EllipticCurvePrivateKey)
class EllipticCurvePrivateKey(object):
    def __init__(self, private_key, x, y, curve):
        if (
            not isinstance(private_key, six.integer_types) or
            not isinstance(x, six.integer_types) or
            not isinstance(y, six.integer_types)
        ):
            raise TypeError("private_key, x and y must be integers.")

        if not isinstance(curve, interfaces.EllipticCurve):
            raise TypeError("curve must provide the EllipticCurve interface.")

        self._private_key = private_key
        self._y = y
        self._x = x
        self._curve = curve

    @classmethod
    def generate(cls, curve, backend):
        return backend.generate_ecdsa_private_key(curve)

    def signer(self, algorithm, backend):
        return backend.create_ecdsa_signature_ctx(self, algorithm)

    @property
    def key_size(self):
        return self._curve.key_size

    @property
    def private_key(self):
        return self._private_key

    @property
    def x(self):
        return self._x

    @property
    def y(self):
        return self._y

    @property
    def curve(self):
        return self._curve

    def public_key(self):
        return EllipticCurvePublicKey(self._x, self._y, self._curve)
