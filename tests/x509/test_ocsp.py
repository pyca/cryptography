# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

import pytest

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from ..utils import load_vectors_from_file


def _load_data(filename, loader):
    return load_vectors_from_file(
        filename=filename,
        loader=lambda data: loader(data.read()),
        mode="rb"
    )


class TestOCSPRequest(object):
    def test_bad_request(self):
        with pytest.raises(ValueError):
            ocsp.load_der_ocsp_request(b"invalid")

    def test_load_request_one_item(self):
        req = _load_data(
            os.path.join("x509", "ocsp", "req-sha1.der"),
            ocsp.load_der_ocsp_request,
        )
        assert len(req) == 1
        assert req[0].issuer_name_hash == (b"8\xcaF\x8c\x07D\x8d\xf4\x81\x96"
                                           b"\xc7mmLpQ\x9e`\xa7\xbd")
        assert req[0].issuer_key_hash == (b"yu\xbb\x84:\xcb,\xdez\t\xbe1"
                                          b"\x1bC\xbc\x1c*MSX")
        assert isinstance(req[0].hash_algorithm, hashes.SHA1)
        assert req[0].serial_number == int(
            "98D9E5C0B4C373552DF77C5D0F1EB5128E4945F9", 16
        )

    def test_load_request_multiple_items(self):
        req = _load_data(
            os.path.join("x509", "ocsp", "req-multi-sha1.der"),
            ocsp.load_der_ocsp_request,
        )
        assert len(req) == 2
        assert req[0].issuer_name_hash == (b"8\xcaF\x8c\x07D\x8d\xf4\x81\x96"
                                           b"\xc7mmLpQ\x9e`\xa7\xbd")
        assert req[0].issuer_key_hash == (b"yu\xbb\x84:\xcb,\xdez\t\xbe1"
                                          b"\x1bC\xbc\x1c*MSX")
        assert isinstance(req[0].hash_algorithm, hashes.SHA1)
        assert req[0].serial_number == int(
            "98D9E5C0B4C373552DF77C5D0F1EB5128E4945F9", 16
        )
        assert req[1].issuer_name_hash == (b"8\xcaF\x8c\x07D\x8d\xf4\x81\x96"
                                           b"\xc7mmLpQ\x9e`\xa7\xbd")
        assert req[1].issuer_key_hash == (b"yu\xbb\x84:\xcb,\xdez\t\xbe1"
                                          b"\x1bC\xbc\x1c*MSX")
        assert isinstance(req[1].hash_algorithm, hashes.SHA1)
        assert req[1].serial_number == int(
            "98D9E5C0B4C373552DF77C5D0F1EB5128E4945F0", 16
        )

    def test_iter(self):
        req = _load_data(
            os.path.join("x509", "ocsp", "req-multi-sha1.der"),
            ocsp.load_der_ocsp_request,
        )
        for request in req:
            assert isinstance(request, ocsp.Request)

    def test_indexing_ocsp_request(self):
        req = _load_data(
            os.path.join("x509", "ocsp", "req-multi-sha1.der"),
            ocsp.load_der_ocsp_request,
        )
        assert req[1].serial_number == req[-1].serial_number
        assert len(req[0:2]) == 2
        assert req[1:2][0].serial_number == int(
            "98D9E5C0B4C373552DF77C5D0F1EB5128E4945F0", 16
        )
        with pytest.raises(IndexError):
            req[10]

    def test_invalid_hash_algorithm(self):
        req = _load_data(
            os.path.join("x509", "ocsp", "req-invalid-hash-alg.der"),
            ocsp.load_der_ocsp_request,
        )
        with pytest.raises(UnsupportedAlgorithm):
            req[0].hash_algorithm

    def test_serialize_request(self):
        req_bytes = load_vectors_from_file(
            filename=os.path.join("x509", "ocsp", "req-sha1.der"),
            loader=lambda data: data.read(),
            mode="rb"
        )
        req = ocsp.load_der_ocsp_request(req_bytes)
        assert req.public_bytes(serialization.Encoding.DER) == req_bytes

    def test_invalid_serialize_encoding(self):
        req = _load_data(
            os.path.join("x509", "ocsp", "req-sha1.der"),
            ocsp.load_der_ocsp_request,
        )
        with pytest.raises(ValueError):
            req.public_bytes("invalid")
        with pytest.raises(ValueError):
            req.public_bytes(serialization.Encoding.PEM)
