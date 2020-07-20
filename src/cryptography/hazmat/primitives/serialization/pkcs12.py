# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography.hazmat.backends import default_backend


def load_key_and_certificates(data, password, backend):
    return backend.load_key_and_certificates_from_pkcs12(data, password)


def serialize_key_and_certificates(name, key, cert, cas, key_encryption):
    # TODO: this should probably just determine backend from key/cert/whatever
    # TODO: what is the minimum to generate a PKCS12 structure? Users must
    # provide one of key/cert/cas minimally right?
    return default_backend().serialize_key_and_certificates_to_pkcs12(
        name, key, cert, cas, key_encryption
    )
