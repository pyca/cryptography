# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function


def load_key_and_certificates(data, password, backend):
    return backend.load_key_and_certificates_from_pkcs12(data, password)


def store_key_and_certificates(
    key, cert, additional_certificates, password, backend, name=None,
        nid_key=0, nid_cert=0, iter_=0, mac_iter=0, keytype=0):
    return backend.store_key_and_certificates_in_pkcs12(
        password, name, key, cert, additional_certificates, nid_key, nid_cert,
        iter_, mac_iter, keytype)
