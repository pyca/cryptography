# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from enum import Enum


# TODO: document this
class X509Version(Enum):
    v1 = 0
    v3 = 2


# TODO: document this
def load_pem_x509_certificate(data, backend):
    return backend.load_pem_x509_certificate(data)


# TODO: document this
def load_der_x509_certificate(data, backend):
    return backend.load_der_x509_certificate(data)
