# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc

import six


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
