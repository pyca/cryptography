# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from __future__ import absolute_import, division, print_function

import itertools
import os

import pytest

from cryptography import exceptions, utils
from cryptography.hazmat.primitives import hashes, interfaces
from cryptography.hazmat.primitives.asymmetric import ec

from ...utils import (
    raises_unsupported_algorithm,
    load_vectors_from_file, load_fips_ecdsa_key_pair_vectors,
    load_fips_ecdsa_signing_vectors
)


_CURVE_TYPES = {
    "secp192r1": ec.secp192r1,
    "secp224r1": ec.secp224r1,
    "secp256r1": ec.secp256r1,
    "secp384r1": ec.secp384r1,
    "secp521r1": ec.secp521r1,

    "sect163k1": ec.sect163k1,
    "sect233k1": ec.sect233k1,
    "sect283k1": ec.sect283k1,
    "sect409k1": ec.sect409k1,
    "sect571k1": ec.sect571k1,

    "sect163r2": ec.sect163r2,
    "sect233r1": ec.sect233r1,
    "sect283r1": ec.sect283r1,
    "sect409r1": ec.sect409r1,
    "sect571r1": ec.sect571r1,
}

_HASH_TYPES = {
    "SHA-1": hashes.SHA1,
    "SHA-224": hashes.SHA224,
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
    "SHA-512": hashes.SHA512,
}


def _skip_ecdsa_vector(backend, curve_type, hash_type):
    if not backend.elliptic_curve_supported(
        ec.ECDSA(hash_type()),
        curve_type()
    ):
        pytest.skip("ECDSA not supported with this hash and curve")


@pytest.mark.ecdsa
class TestECDSAVectors(object):
    @pytest.mark.parametrize(
        ("vector", "hash_type"),
        list(itertools.product(
            load_vectors_from_file(
                os.path.join(
                    "asymmetric", "ECDSA", "FIPS_186-3", "KeyPair.rsp"),
                load_fips_ecdsa_key_pair_vectors
            ),
            _HASH_TYPES.values()
        ))
    )
    def test_signing_with_example_keys(self, backend, vector, hash_type):
        curve_type = _CURVE_TYPES[vector['curve']]

        _skip_ecdsa_vector(backend, curve_type, hash_type)

        key = ec.EllipticCurvePrivateKey(
            vector['d'],
            vector['x'],
            vector['y'],
            curve_type()
        )

        assert key.private_key
        assert key.x
        assert key.y
        assert key.curve.name

        pkey = key.public_key()
        assert pkey

        assert key.x == pkey.x
        assert key.y == pkey.y
        assert key.curve.name == pkey.curve.name

        signer = key.signer(ec.ECDSA(hash_type()), backend)
        signer.update(b"YELLOW SUBMARINE")
        signature = signer.finalize()

        verifier = pkey.verifier(signature, ec.ECDSA(hash_type()), backend)
        verifier.update(b"YELLOW SUBMARINE")
        verifier.verify()

    @pytest.mark.parametrize(
        "curve", _CURVE_TYPES.values()
    )
    def test_generate_vector_curves(self, backend, curve):
        key = ec.EllipticCurvePrivateKey.generate(curve(), backend)
        assert key

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join(
                "asymmetric", "ECDSA", "FIPS_186-3", "SigGen.txt"),
            load_fips_ecdsa_signing_vectors
        )
    )
    def test_signatures(self, backend, vector):
        hash_type = _HASH_TYPES[vector['digest_algorithm']]
        curve_type = _CURVE_TYPES[vector['curve']]

        _skip_ecdsa_vector(backend, curve_type, hash_type)

        key = ec.EllipticCurvePublicKey(
            vector['x'],
            vector['y'],
            curve_type()
        )

        signature = backend.ecdsa_signature_from_components(
            vector['r'],
            vector['s']
        )

        verifier = key.verifier(
            signature,
            ec.ECDSA(hash_type()),
            backend
        )
        verifier.update(vector['message'])
        assert verifier.verify()

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join(
                "asymmetric", "ECDSA", "FIPS_186-3", "SigVer.rsp"),
            load_fips_ecdsa_signing_vectors
        )
    )
    def test_signature_failures(self, backend, vector):
        hash_type = _HASH_TYPES[vector['digest_algorithm']]
        curve_type = _CURVE_TYPES[vector['curve']]

        _skip_ecdsa_vector(backend, curve_type, hash_type)

        key = ec.EllipticCurvePublicKey(
            vector['x'],
            vector['y'],
            curve_type()
        )

        signature = backend.ecdsa_signature_from_components(
            vector['r'],
            vector['s']
        )

        verifier = key.verifier(
            signature,
            ec.ECDSA(hash_type()),
            backend
        )
        verifier.update(vector['message'])

        if vector["fail"] is True:
            with pytest.raises(exceptions.InvalidSignature):
                verifier.verify()
        else:
            verifier.verify()

    def test_generate_unknown_curve(self, backend):
        @utils.register_interface(interfaces.EllipticCurve)
        class DummyCurve(object):
            name = "dummy-curve"

        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_ELLIPTIC_CURVE
        ):
            ec.EllipticCurvePrivateKey.generate(DummyCurve(), backend)


class TestECInterfaces(object):
    def test_invalid_private_key_argument_types(self):
        with pytest.raises(TypeError):
            ec.EllipticCurvePrivateKey(None, None, None, None)

    def test_invalid_public_key_argument_types(self):
        with pytest.raises(TypeError):
            ec.EllipticCurvePublicKey(None, None, None)
