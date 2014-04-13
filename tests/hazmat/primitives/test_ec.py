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


@pytest.mark.ecdsa
@pytest.mark.supported(
    only_if=lambda backend: backend.ecdsa_supported(),
    skip_message="This backend does not support ECDSA"
)
class TestECDSAVectors(object):
    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join(
                "asymmetric", "ECDSA", "FIPS_186-3", "KeyPair.rsp"),
            load_fips_ecdsa_key_pair_vectors
        )
    )
    def test_load_example_keys(self, backend, vector):
        @utils.register_interface(interfaces.EllipticCurve)
        class Curve(object):
            name = vector['curve']

        key = ec.EllipticCurvePrivateKey(
            vector['d'],
            vector['x'],
            vector['y'],
            Curve()
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

    @pytest.mark.parametrize(
        "curve",
        set(
            key['curve']
            for key in load_vectors_from_file(
                os.path.join(
                    "asymmetric", "ECDSA", "FIPS_186-3", "KeyPair.rsp"),
                load_fips_ecdsa_key_pair_vectors
            )
        )
    )
    def test_generate_vector_curves(self, backend, curve):
        @utils.register_interface(interfaces.EllipticCurve)
        class Curve(object):
            name = curve

        key = ec.EllipticCurvePrivateKey.generate(Curve(), backend)
        assert key

    def test_generate_unknown_curve(self, backend):
        @utils.register_interface(interfaces.EllipticCurve)
        class DummyCurve(object):
            name = "dummy-curve"

        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_ELLIPTIC_CURVE
        ):
            ec.EllipticCurvePrivateKey.generate(DummyCurve(), backend)

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join(
                "asymmetric", "ECDSA", "FIPS_186-3", "SigGen.txt"),
            load_fips_ecdsa_signing_vectors
        )
    )
    def test_signing(self, backend, vector):
        return
        @utils.register_interface(interfaces.EllipticCurve)
        class Curve(object):
            name = vector['curve']

        key = ec.ECDSAPublicKey(
            vector['x'],
            vector['y'],
            Curve()
        )

        hash_map = {
            "SHA-1": hashes.SHA1,
            "SHA-224": hashes.SHA224,
            "SHA-256": hashes.SHA256,
            "SHA-384": hashes.SHA384,
            "SHA-512": hashes.SHA512,
        }

        verifier = key.verifier(
            None,
            hash_map[vector['digest_algorithm']](),
            backend
        )
        verifier.update(vector['message'])
        assert verifier.verify()


class TestEC(object):
    def test_invalid_private_key_argument_types(self):
        with pytest.raises(TypeError):
            ec.EllipticCurvePrivateKey(None, None, None, None)

    def test_invalid_public_key_argument_types(self):
        with pytest.raises(TypeError):
            ec.EllipticCurvePublicKey(None, None, None)
