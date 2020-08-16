# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography.hazmat.backends import _get_backend


def load_pem_pkcs7_certificates(data):
    backend = _get_backend(None)
    return backend.load_pem_pkcs7_certificates(data)


def load_der_pkcs7_certificates(data):
    backend = _get_backend(None)
    return backend.load_der_pkcs7_certificates(data)
