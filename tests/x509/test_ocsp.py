# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

import pytest

from cryptography.hazmat.backends.interfaces import (
    OCSPBackend
)
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ocsp

from ..utils import load_vectors_from_file


def _load_data(filename, loader, backend):
    return load_vectors_from_file(
        filename=filename,
        loader=lambda data: loader(data.read(), backend),
        mode="rb"
    )


@pytest.mark.requires_backend_interface(interface=OCSPBackend)
class TestOCSPRequest(object):
    def test_load_request_one_item(self, backend):
        req = _load_data(
            os.path.join("x509", "ocsp", "req-sha1.der"),
            ocsp.load_der_ocsp_request,
            backend
        )
        len(req) == 1
        assert req[0].issuer_name_hash == (b"8\xcaF\x8c\x07D\x8d\xf4\x81\x96"
                                           b"\xc7mmLpQ\x9e`\xa7\xbd")
        assert req[0].issuer_key_hash == (b"yu\xbb\x84:\xcb,\xdez\t\xbe1"
                                          b"\x1bC\xbc\x1c*MSX")
        assert isinstance(req[0].hash_algorithm, hashes.SHA1)
        assert req[0].serial_number == int(
            "98D9E5C0B4C373552DF77C5D0F1EB5128E4945F9", 16
        )

    # TODO
    def test_load_request_multiple_items(self, backend):
        pass
