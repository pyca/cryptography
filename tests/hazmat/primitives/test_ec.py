# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
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
from cryptography.hazmat.backends.interfaces import EllipticCurveBackend
from cryptography.hazmat.primitives import hashes, interfaces
from cryptography.hazmat.primitives.asymmetric import ec

from ...utils import (
    der_encode_dsa_signature, load_fips_ecdsa_key_pair_vectors,
    load_fips_ecdsa_signing_vectors, load_vectors_from_file,
    raises_unsupported_algorithm
)

_HASH_TYPES = {
    "SHA-1": hashes.SHA1,
    "SHA-224": hashes.SHA224,
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
    "SHA-512": hashes.SHA512,
}


def _skip_ecdsa_vector(backend, curve_type, hash_type):
    if not backend.elliptic_curve_signature_algorithm_supported(
        ec.ECDSA(hash_type()),
        curve_type()
    ):
        pytest.skip(
            "ECDSA not supported with this hash {0} and curve {1}".format(
                hash_type().name, curve_type().name
            )
        )


def _skip_curve_unsupported(backend, curve):
    if not backend.elliptic_curve_supported(curve):
        pytest.skip(
            "Curve {0} is not supported by this backend {1}".format(
                curve.name, backend
            )
        )


@utils.register_interface(interfaces.EllipticCurve)
class DummyCurve(object):
    name = "dummy-curve"
    key_size = 1


@utils.register_interface(interfaces.EllipticCurveSignatureAlgorithm)
class DummySignatureAlgorithm(object):
    pass


@utils.register_interface(EllipticCurveBackend)
class DeprecatedDummyECBackend(object):
    def elliptic_curve_private_key_from_numbers(self, numbers):
        return b"private_key"

    def elliptic_curve_public_key_from_numbers(self, numbers):
        return b"public_key"


@pytest.mark.elliptic
def test_skip_curve_unsupported(backend):
    with pytest.raises(pytest.skip.Exception):
        _skip_curve_unsupported(backend, DummyCurve())


def test_ec_numbers():
    numbers = ec.EllipticCurvePrivateNumbers(
        1,
        ec.EllipticCurvePublicNumbers(
            2, 3, DummyCurve()
        )
    )

    assert numbers.private_value == 1
    assert numbers.public_numbers.x == 2
    assert numbers.public_numbers.y == 3
    assert isinstance(numbers.public_numbers.curve, DummyCurve)

    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(
            None,
            ec.EllipticCurvePublicNumbers(
                2, 3, DummyCurve()
            )
        )

    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(
            1,
            ec.EllipticCurvePublicNumbers(
                None, 3, DummyCurve()
            )
        )

    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(
            1,
            ec.EllipticCurvePublicNumbers(
                2, None, DummyCurve()
            )
        )

    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(
            1,
            ec.EllipticCurvePublicNumbers(
                2, 3, None
            )
        )

    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(
            1,
            None
        )


@pytest.mark.elliptic
class TestECWithNumbers(object):
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
    def test_with_numbers(self, backend, vector, hash_type):
        curve_type = ec._CURVE_TYPES[vector['curve']]

        _skip_ecdsa_vector(backend, curve_type, hash_type)

        key = ec.EllipticCurvePrivateNumbers(
            vector['d'],
            ec.EllipticCurvePublicNumbers(
                vector['x'],
                vector['y'],
                curve_type()
            )
        ).private_key(backend)
        assert key

        if isinstance(key, interfaces.EllipticCurvePrivateKeyWithNumbers):
            priv_num = key.private_numbers()
            assert priv_num.private_value == vector['d']
            assert priv_num.public_numbers.x == vector['x']
            assert priv_num.public_numbers.y == vector['y']
            assert curve_type().name == priv_num.public_numbers.curve.name


@pytest.mark.elliptic
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
        curve_type = ec._CURVE_TYPES[vector['curve']]

        _skip_ecdsa_vector(backend, curve_type, hash_type)

        key = ec.EllipticCurvePrivateNumbers(
            vector['d'],
            ec.EllipticCurvePublicNumbers(
                vector['x'],
                vector['y'],
                curve_type()
            )
        ).private_key(backend)
        assert key

        pkey = key.public_key()
        assert pkey

        signer = key.signer(ec.ECDSA(hash_type()))
        signer.update(b"YELLOW SUBMARINE")
        signature = signer.finalize()

        verifier = pkey.verifier(signature, ec.ECDSA(hash_type()))
        verifier.update(b"YELLOW SUBMARINE")
        verifier.verify()

    @pytest.mark.parametrize(
        "curve", ec._CURVE_TYPES.values()
    )
    def test_generate_vector_curves(self, backend, curve):
        _skip_curve_unsupported(backend, curve())

        key = ec.generate_private_key(curve(), backend)
        assert key
        assert isinstance(key.curve, curve)
        assert key.curve.key_size

        pkey = key.public_key()
        assert pkey
        assert isinstance(pkey.curve, curve)
        assert key.curve.key_size == pkey.curve.key_size

    def test_generate_unknown_curve(self, backend):
        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_ELLIPTIC_CURVE
        ):
            ec.generate_private_key(DummyCurve(), backend)

        assert backend.elliptic_curve_signature_algorithm_supported(
            ec.ECDSA(hashes.SHA256()),
            DummyCurve()
        ) is False

    def test_unknown_signature_algoritm(self, backend):
        _skip_curve_unsupported(backend, ec.SECP192R1())

        key = ec.generate_private_key(ec.SECP192R1(), backend)

        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            key.signer(DummySignatureAlgorithm())

        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            key.public_key().verifier(b"", DummySignatureAlgorithm())

        assert backend.elliptic_curve_signature_algorithm_supported(
            DummySignatureAlgorithm(),
            ec.SECP192R1()
        ) is False

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
        curve_type = ec._CURVE_TYPES[vector['curve']]

        _skip_ecdsa_vector(backend, curve_type, hash_type)

        key = ec.EllipticCurvePublicNumbers(
            vector['x'],
            vector['y'],
            curve_type()
        ).public_key(backend)

        signature = der_encode_dsa_signature(
            vector['r'],
            vector['s']
        )

        verifier = key.verifier(
            signature,
            ec.ECDSA(hash_type())
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
        curve_type = ec._CURVE_TYPES[vector['curve']]

        _skip_ecdsa_vector(backend, curve_type, hash_type)

        key = ec.EllipticCurvePublicNumbers(
            vector['x'],
            vector['y'],
            curve_type()
        ).public_key(backend)

        signature = der_encode_dsa_signature(
            vector['r'],
            vector['s']
        )

        verifier = key.verifier(
            signature,
            ec.ECDSA(hash_type())
        )
        verifier.update(vector['message'])

        if vector["fail"] is True:
            with pytest.raises(exceptions.InvalidSignature):
                verifier.verify()
        else:
            verifier.verify()

    def test_deprecated_public_private_key_load(self):
        b = DeprecatedDummyECBackend()
        pub_numbers = ec.EllipticCurvePublicNumbers(
            2,
            3,
            ec.SECT283K1()
        )
        numbers = ec.EllipticCurvePrivateNumbers(1, pub_numbers)
        assert numbers.private_key(b) == b"private_key"
        assert pub_numbers.public_key(b) == b"public_key"
