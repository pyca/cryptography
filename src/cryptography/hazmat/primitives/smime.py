# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from enum import Enum

from cryptography import x509
from cryptography.hazmat.backends import _get_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.utils import _check_byteslike


class SMIMESignatureBuilder(object):
    def __init__(self, data=None, signers=[]):
        self._data = data
        self._signers = signers

    def set_data(self, data):
        _check_byteslike("data", data)
        if self._data is not None:
            raise ValueError("data may only be set once")

        return SMIMESignatureBuilder(data, self._signers)

    def add_signer(self, certificate, private_key, hash_algorithm):
        if not isinstance(
            hash_algorithm,
            (
                hashes.SHA1,
                hashes.SHA224,
                hashes.SHA256,
                hashes.SHA384,
                hashes.SHA512,
            ),
        ):
            raise TypeError(
                "hash_algorithm must be one of hashes.SHA1, SHA224, "
                "SHA256, SHA384, or SHA512"
            )
        if not isinstance(certificate, x509.Certificate):
            raise TypeError("certificate must be a x509.Certificate")

        if not isinstance(
            private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)
        ):
            raise TypeError("Only RSA & EC keys are supported at this time.")

        return SMIMESignatureBuilder(
            self._data,
            self._signers + [(certificate, private_key, hash_algorithm)],
        )

    def sign(self, encoding, options, backend=None):
        if len(self._signers) == 0:
            raise ValueError("Must have at least one signer")
        if self._data is None:
            raise ValueError("You must add data to sign")
        options = list(options)
        if not all(isinstance(x, SMIMEOptions) for x in options):
            raise ValueError("options must be from the SMIMEOptions enum")
        if (
            encoding is not serialization.Encoding.PEM
            and encoding is not serialization.Encoding.DER
        ):
            raise ValueError("Must be PEM or DER from the Encoding enum")

        # Text is a meaningless option unless it is accompanied by
        # DetachedSignature
        if (
            SMIMEOptions.Text in options
            and SMIMEOptions.DetachedSignature not in options
        ):
            raise ValueError(
                "When passing the Text option you must also pass "
                "DetachedSignature"
            )

        if (
            SMIMEOptions.Text in options
            and encoding is serialization.Encoding.DER
        ):
            raise ValueError(
                "The Text option does nothing when serializing to DER"
            )

        # No attributes implies no capabilities so we'll error if you try to
        # pass both.
        if (
            SMIMEOptions.NoAttributes in options
            and SMIMEOptions.NoCapabilities in options
        ):
            raise ValueError(
                "NoAttributes is a superset of NoCapabilities. Do not pass "
                "both values."
            )

        backend = _get_backend(backend)
        return backend.smime_sign(self, encoding, options)


class SMIMEOptions(Enum):
    Text = "Add text/plain MIME type"
    Binary = "Don't translate input data into canonical MIME format"
    DetachedSignature = "Don't embed data in the PKCS7 structure"
    NoCapabilities = "Don't embed SMIME capabilities"
    NoAttributes = "Don't embed authenticatedAttributes"
