# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc

import six

from cryptography import utils
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.kdf import KeyDerivationFunction


@six.add_metaclass(abc.ABCMeta)
class KeyExchangeFunction(object):
    @abc.abstractproperty
    def private_key(self):
        """
        The private key associated to the Key Exchange Function.
        """

    @abc.abstractmethod
    def public_key(self):
        """
        The public key associated to the private_key.
        """

    @abc.abstractmethod
    def compute_key(self, peer_public_key, kdf):
        """
        Computes and returns a shared key.
        """


@utils.register_interface(KeyExchangeFunction)
class ECDH(object):
    def __init__(self, private_key, backend):
        if not isinstance(private_key, EllipticCurvePrivateKey):
            raise TypeError("Private Key must be a EllipticCurvePrivateKey")
        self._private_key = private_key
        self._backend = backend

    private_key = utils.read_only_property("_private_key")

    def public_key(self):
        return self._private_key.public_key()

    def compute_key(self, peer_public_key, kdf):
        if not isinstance(peer_public_key, EllipticCurvePublicKey):
            raise TypeError("Peer Public Key must be a EllipticCurvePublicKey")
        if not isinstance(kdf, KeyDerivationFunction):
            raise TypeError("KDF must be a KeyDerivationFunction")
        return self._backend.ecdh_compute_key(self._private_key,
                                              peer_public_key, kdf)
