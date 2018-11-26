# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class PKCS12(object):
    @abc.abstractproperty
    def private_key(self):
        """
        The private key inside the PKCS12 object.
        """

    @abc.abstractproperty
    def certificate(self):
        """
        The certificate associated with the private key.
        """

    @abc.abstractproperty
    def additional_certificates(self):
        """
        Additional certificates inside the PKCS12 object.
        """
