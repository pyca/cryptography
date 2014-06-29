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

import warnings

import six

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.backends.interfaces import DSABackend
from cryptography.hazmat.primitives import interfaces


def generate_parameters(key_size, backend):
    return backend.generate_dsa_parameters(key_size)


def generate_private_key(key_size, backend):
    return backend.generate_dsa_private_key_and_parameters(key_size)


def _check_dsa_parameters(parameters):
    if (utils.bit_length(parameters.p),
        utils.bit_length(parameters.q)) not in (
            (1024, 160),
            (2048, 256),
            (3072, 256)):
        raise ValueError("p and q lengths must be "
                         "one of these pairs (1024, 160) or (2048, 256) "
                         "or (3072, 256).")

    if not (1 < parameters.g < parameters.p):
        raise ValueError("g, p don't satisfy 1 < g < p.")


def _check_dsa_private_numbers(numbers):
    parameters = numbers.public_numbers.parameter_numbers
    _check_dsa_parameters(parameters)
    if numbers.x <= 0 or numbers.x >= parameters.q:
        raise ValueError("x must be > 0 and < q.")

    if numbers.public_numbers.y != pow(parameters.g, numbers.x, parameters.p):
        raise ValueError("y must be equal to (g ** x % p).")


@utils.register_interface(interfaces.DSAParameters)
class DSAParameters(object):
    def __init__(self, modulus, subgroup_order, generator):
        warnings.warn(
            "The DSAParameters class is deprecated and will be removed in a "
            "future version.",
            utils.DeprecatedIn05,
            stacklevel=2
        )
        _check_dsa_parameters(
            DSAParameterNumbers(
                p=modulus,
                q=subgroup_order,
                g=generator
            )
        )

        self._modulus = modulus
        self._subgroup_order = subgroup_order
        self._generator = generator

    @classmethod
    def generate(cls, key_size, backend):
        warnings.warn(
            "generate is deprecated and will be removed in a future version.",
            utils.DeprecatedIn05,
            stacklevel=2
        )
        if not isinstance(backend, DSABackend):
            raise UnsupportedAlgorithm(
                "Backend object does not implement DSABackend.",
                _Reasons.BACKEND_MISSING_INTERFACE
            )

        parameters = backend.generate_dsa_parameters(key_size)
        numbers = parameters.parameter_numbers()
        return cls(
            modulus=numbers.p,
            subgroup_order=numbers.q,
            generator=numbers.g
        )

    @property
    def modulus(self):
        return self._modulus

    @property
    def subgroup_order(self):
        return self._subgroup_order

    @property
    def generator(self):
        return self._generator

    @property
    def p(self):
        return self.modulus

    @property
    def q(self):
        return self.subgroup_order

    @property
    def g(self):
        return self.generator


@utils.register_interface(interfaces.DSAPrivateKey)
class DSAPrivateKey(object):
    def __init__(self, modulus, subgroup_order, generator, x, y):
        warnings.warn(
            "The DSAPrivateKey class is deprecated and will be removed in a "
            "future version.",
            utils.DeprecatedIn05,
            stacklevel=2
        )
        if (
            not isinstance(x, six.integer_types) or
            not isinstance(y, six.integer_types)
        ):
            raise TypeError("DSAPrivateKey arguments must be integers.")

        _check_dsa_private_numbers(
            DSAPrivateNumbers(
                public_numbers=DSAPublicNumbers(
                    parameter_numbers=DSAParameterNumbers(
                        p=modulus,
                        q=subgroup_order,
                        g=generator
                    ),
                    y=y
                ),
                x=x
            )
        )

        self._modulus = modulus
        self._subgroup_order = subgroup_order
        self._generator = generator
        self._x = x
        self._y = y

    @classmethod
    def generate(cls, parameters, backend):
        warnings.warn(
            "generate is deprecated and will be removed in a future version.",
            utils.DeprecatedIn05,
            stacklevel=2
        )
        if not isinstance(backend, DSABackend):
            raise UnsupportedAlgorithm(
                "Backend object does not implement DSABackend.",
                _Reasons.BACKEND_MISSING_INTERFACE
            )

        key = backend.generate_dsa_private_key(parameters)
        private_numbers = key.private_numbers()
        return cls(
            modulus=private_numbers.public_numbers.parameter_numbers.p,
            subgroup_order=private_numbers.public_numbers.parameter_numbers.q,
            generator=private_numbers.public_numbers.parameter_numbers.g,
            x=private_numbers.x,
            y=private_numbers.public_numbers.y
        )

    def signer(self, algorithm, backend):
        if not isinstance(backend, DSABackend):
            raise UnsupportedAlgorithm(
                "Backend object does not implement DSABackend.",
                _Reasons.BACKEND_MISSING_INTERFACE
            )

        return backend.create_dsa_signature_ctx(self, algorithm)

    @property
    def key_size(self):
        return utils.bit_length(self._modulus)

    def public_key(self):
        return DSAPublicKey(self._modulus, self._subgroup_order,
                            self._generator, self.y)

    @property
    def x(self):
        return self._x

    @property
    def y(self):
        return self._y

    def parameters(self):
        return DSAParameters(self._modulus, self._subgroup_order,
                             self._generator)


@utils.register_interface(interfaces.DSAPublicKey)
class DSAPublicKey(object):
    def __init__(self, modulus, subgroup_order, generator, y):
        warnings.warn(
            "The DSAPublicKey class is deprecated and will be removed in a "
            "future version.",
            utils.DeprecatedIn05,
            stacklevel=2
        )
        _check_dsa_parameters(
            DSAParameterNumbers(
                p=modulus,
                q=subgroup_order,
                g=generator
            )
        )
        if not isinstance(y, six.integer_types):
            raise TypeError("y must be an integer.")

        self._modulus = modulus
        self._subgroup_order = subgroup_order
        self._generator = generator
        self._y = y

    def verifier(self, signature, algorithm, backend):
        if not isinstance(backend, DSABackend):
            raise UnsupportedAlgorithm(
                "Backend object does not implement DSABackend.",
                _Reasons.BACKEND_MISSING_INTERFACE
            )

        return backend.create_dsa_verification_ctx(self, signature,
                                                   algorithm)

    @property
    def key_size(self):
        return utils.bit_length(self._modulus)

    @property
    def y(self):
        return self._y

    def parameters(self):
        return DSAParameters(self._modulus, self._subgroup_order,
                             self._generator)


class DSAParameterNumbers(object):
    def __init__(self, p, q, g):
        if (
            not isinstance(p, six.integer_types) or
            not isinstance(q, six.integer_types) or
            not isinstance(g, six.integer_types)
        ):
            raise TypeError(
                "DSAParameterNumbers p, q, and g arguments must be integers."
            )

        self._p = p
        self._q = q
        self._g = g

    @property
    def p(self):
        return self._p

    @property
    def q(self):
        return self._q

    @property
    def g(self):
        return self._g

    def parameters(self, backend):
        return backend.load_dsa_parameter_numbers(self)


class DSAPublicNumbers(object):
    def __init__(self, y, parameter_numbers):
        if not isinstance(y, six.integer_types):
            raise TypeError("DSAPublicNumbers y argument must be an integer.")

        if not isinstance(parameter_numbers, DSAParameterNumbers):
            raise TypeError(
                "parameter_numbers must be a DSAParameterNumbers instance."
            )

        self._y = y
        self._parameter_numbers = parameter_numbers

    @property
    def y(self):
        return self._y

    @property
    def parameter_numbers(self):
        return self._parameter_numbers

    def public_key(self, backend):
        return backend.load_dsa_public_numbers(self)


class DSAPrivateNumbers(object):
    def __init__(self, x, public_numbers):
        if not isinstance(x, six.integer_types):
            raise TypeError("DSAPrivateNumbers x argument must be an integer.")

        if not isinstance(public_numbers, DSAPublicNumbers):
            raise TypeError(
                "public_numbers must be a DSAPublicNumbers instance."
            )
        self._public_numbers = public_numbers
        self._x = x

    @property
    def x(self):
        return self._x

    @property
    def public_numbers(self):
        return self._public_numbers

    def private_key(self, backend):
        return backend.load_dsa_private_numbers(self)
