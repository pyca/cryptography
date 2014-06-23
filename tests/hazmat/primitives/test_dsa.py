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

from cryptography.exceptions import (
    AlreadyFinalized, InvalidSignature, _Reasons)
from cryptography.hazmat.primitives import hashes, interfaces
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.utils import bit_length

from .fixtures_dsa import (
    DSA_KEY_1024, DSA_KEY_2048, DSA_KEY_3072
)
from ...utils import (
    der_encode_dsa_signature, load_fips_dsa_key_pair_vectors,
    load_fips_dsa_sig_vectors, load_vectors_from_file,
    raises_unsupported_algorithm
)


def _check_dsa_private_key(skey):
    assert skey
    assert skey.x
    assert skey.y
    assert skey.key_size

    skey_parameters = skey.parameters()
    assert skey_parameters
    assert skey_parameters.modulus
    assert skey_parameters.subgroup_order
    assert skey_parameters.generator
    assert skey_parameters.modulus == skey_parameters.p
    assert skey_parameters.subgroup_order == skey_parameters.q
    assert skey_parameters.generator == skey_parameters.g

    pkey = skey.public_key()
    assert pkey
    assert skey.y == pkey.y
    assert skey.key_size == pkey.key_size

    pkey_parameters = pkey.parameters()
    assert pkey_parameters
    assert pkey_parameters.modulus
    assert pkey_parameters.subgroup_order
    assert pkey_parameters.generator
    assert pkey_parameters.modulus == pkey_parameters.p
    assert pkey_parameters.subgroup_order == pkey_parameters.q
    assert pkey_parameters.generator == pkey_parameters.g

    assert skey_parameters.modulus == pkey_parameters.modulus
    assert skey_parameters.subgroup_order == pkey_parameters.subgroup_order
    assert skey_parameters.generator == pkey_parameters.generator


@pytest.mark.dsa
class TestDSA(object):
    def test_generate_dsa_parameters_class_method(self, backend):
        parameters = dsa.DSAParameters.generate(1024, backend)
        assert bit_length(parameters.p) == 1024

    def test_generate_dsa_parameters(self, backend):
        parameters = dsa.generate_parameters(1024, backend)
        assert isinstance(parameters, interfaces.DSAParameters)
        # TODO: withnumbers check like RSA

    def test_generate_invalid_dsa_parameters(self, backend):
        with pytest.raises(ValueError):
            dsa.DSAParameters.generate(1, backend)

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join(
                "asymmetric", "DSA", "FIPS_186-3", "KeyPair.rsp"),
            load_fips_dsa_key_pair_vectors
        )
    )
    def test_generate_dsa_keys(self, vector, backend):
        parameters = dsa.DSAParameterNumbers(
            p=vector['p'],
            q=vector['q'],
            g=vector['g']
        ).parameters(backend)
        skey = dsa.generate_private_key(parameters)
        if isinstance(skey, interfaces.DSAPrivateKeyWithNumbers):
            numbers = skey.private_numbers()
            skey_parameters = numbers.public_numbers.parameter_numbers
            pkey = skey.public_key()
            parameters = pkey.parameters()
            parameter_numbers = parameters.parameter_numbers()
            assert parameter_numbers.p == skey_parameters.p
            assert parameter_numbers.q == skey_parameters.q
            assert parameter_numbers.g == skey_parameters.g
            assert skey_parameters.p == vector['p']
            assert skey_parameters.q == vector['q']
            assert skey_parameters.g == vector['g']
            assert skey.key_size == bit_length(vector['p'])
            assert pkey.key_size == skey.key_size
            public_numbers = pkey.public_numbers()
            assert numbers.public_numbers.y == public_numbers.y
            assert numbers.public_numbers.y == pow(
                skey_parameters.g, numbers.x, skey_parameters.p
            )

    def test_invalid_parameters_argument_types(self):
        with pytest.raises(TypeError):
            dsa.DSAParameters(None, None, None)

    def test_invalid_private_key_argument_types(self):
        with pytest.raises(TypeError):
            dsa.DSAPrivateKey(None, None, None, None, None)

    def test_invalid_public_key_argument_types(self):
        with pytest.raises(TypeError):
            dsa.DSAPublicKey(None, None, None, None)

    def test_load_dsa_example_keys(self):
        parameters = dsa.DSAParameters(
            modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
            subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
            generator=DSA_KEY_1024.public_numbers.parameter_numbers.g
        )

        assert parameters
        assert parameters.modulus
        assert parameters.subgroup_order
        assert parameters.generator
        assert parameters.modulus == parameters.p
        assert parameters.subgroup_order == parameters.q
        assert parameters.generator == parameters.g

        pub_key = dsa.DSAPublicKey(
            modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
            subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
            generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
            y=DSA_KEY_1024.public_numbers.y
        )
        assert pub_key
        assert pub_key.key_size
        assert pub_key.y
        pub_key_parameters = pub_key.parameters()
        assert pub_key_parameters
        assert pub_key_parameters.modulus
        assert pub_key_parameters.subgroup_order
        assert pub_key_parameters.generator

        skey = dsa.DSAPrivateKey(
            modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
            subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
            generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
            y=DSA_KEY_1024.public_numbers.y,
            x=DSA_KEY_1024.x
        )
        assert skey
        _check_dsa_private_key(skey)
        skey_parameters = skey.parameters()
        assert skey_parameters
        assert skey_parameters.modulus
        assert skey_parameters.subgroup_order
        assert skey_parameters.generator

        pkey = dsa.DSAPublicKey(
            modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
            subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
            generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
            y=DSA_KEY_1024.public_numbers.y
        )
        assert pkey
        pkey_parameters = pkey.parameters()
        assert pkey_parameters
        assert pkey_parameters.modulus
        assert pkey_parameters.subgroup_order
        assert pkey_parameters.generator

        pkey2 = skey.public_key()
        assert pkey2
        pkey2_parameters = pkey.parameters()
        assert pkey2_parameters
        assert pkey2_parameters.modulus
        assert pkey2_parameters.subgroup_order
        assert pkey2_parameters.generator

        assert skey_parameters.modulus == pkey_parameters.modulus
        assert skey_parameters.subgroup_order == pkey_parameters.subgroup_order
        assert skey_parameters.generator == pkey_parameters.generator
        assert skey.y == pkey.y
        assert skey.key_size == pkey.key_size

        assert pkey_parameters.modulus == pkey2_parameters.modulus
        assert pkey_parameters.subgroup_order == \
            pkey2_parameters.subgroup_order
        assert pkey_parameters.generator == pkey2_parameters.generator
        assert pkey.y == pkey2.y
        assert pkey.key_size == pkey2.key_size

    def test_invalid_parameters_values(self):
        # Test a modulus < 1024 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 1000,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
            )

        # Test a modulus < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 2000,
                subgroup_order=DSA_KEY_2048.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_2048.public_numbers.parameter_numbers.g,
            )

        # Test a modulus < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 3000,
                subgroup_order=DSA_KEY_3072.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_3072.public_numbers.parameter_numbers.g,
            )

        # Test a modulus > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 3100,
                subgroup_order=DSA_KEY_3072.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_3072.public_numbers.parameter_numbers.g,
            )

        # Test a subgroup_order < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=2 ** 150,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
            )

        # Test a subgroup_order < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=DSA_KEY_2048.public_numbers.parameter_numbers.p,
                subgroup_order=2 ** 250,
                generator=DSA_KEY_2048.public_numbers.parameter_numbers.g
            )

        # Test a subgroup_order > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=DSA_KEY_3072.public_numbers.parameter_numbers.p,
                subgroup_order=2 ** 260,
                generator=DSA_KEY_3072.public_numbers.parameter_numbers.g,
            )

        # Test a modulus, subgroup_order pair of (1024, 256) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_2048.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
            )

        # Test a modulus, subgroup_order pair of (2048, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=DSA_KEY_2048.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_2048.public_numbers.parameter_numbers.g
            )

        # Test a modulus, subgroup_order pair of (3072, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=DSA_KEY_3072.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_3072.public_numbers.parameter_numbers.g,
            )

        # Test a generator < 1
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=0
            )

        # Test a generator = 1
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=1
            )

        # Test a generator > modulus
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=2 ** 1200
            )

    def test_invalid_dsa_private_key_arguments(self):
        # Test a modulus < 1024 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 1000,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                x=DSA_KEY_1024.x,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test a modulus < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 2000,
                subgroup_order=DSA_KEY_2048.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_2048.public_numbers.parameter_numbers.g,
                x=DSA_KEY_2048.x,
                y=DSA_KEY_2048.public_numbers.y
            )

        # Test a modulus < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 3000,
                subgroup_order=DSA_KEY_3072.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                x=DSA_KEY_3072.x,
                y=DSA_KEY_3072.public_numbers.y
            )

        # Test a modulus > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 3100,
                subgroup_order=DSA_KEY_3072.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                x=DSA_KEY_3072.x,
                y=DSA_KEY_3072.public_numbers.y
            )

        # Test a subgroup_order < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=2 ** 150,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                x=DSA_KEY_1024.x,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test a subgroup_order < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_2048.public_numbers.parameter_numbers.p,
                subgroup_order=2 ** 250,
                generator=DSA_KEY_2048.public_numbers.parameter_numbers.g,
                x=DSA_KEY_2048.x,
                y=DSA_KEY_2048.public_numbers.y
            )

        # Test a subgroup_order > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_3072.public_numbers.parameter_numbers.p,
                subgroup_order=2 ** 260,
                generator=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                x=DSA_KEY_3072.x,
                y=DSA_KEY_3072.public_numbers.y
            )

        # Test a modulus, subgroup_order pair of (1024, 256) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_2048.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                x=DSA_KEY_1024.x,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test a modulus, subgroup_order pair of (2048, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_2048.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_2048.public_numbers.parameter_numbers.g,
                x=DSA_KEY_2048.x,
                y=DSA_KEY_2048.public_numbers.y
            )

        # Test a modulus, subgroup_order pair of (3072, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_3072.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                x=DSA_KEY_3072.x,
                y=DSA_KEY_3072.public_numbers.y
            )

        # Test a generator < 1
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=0,
                x=DSA_KEY_1024.x,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test a generator = 1
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=1,
                x=DSA_KEY_1024.x,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test a generator > modulus
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=2 ** 1200,
                x=DSA_KEY_1024.x,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test x = 0
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                x=0,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test x < 0
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                x=-2,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test x = subgroup_order
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                x=2 ** 159,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test x > subgroup_order
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                x=2 ** 200,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test y != (generator ** x) % modulus
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                x=DSA_KEY_1024.x,
                y=2 ** 100
            )

        # Test a non-integer y value
        with pytest.raises(TypeError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                x=DSA_KEY_1024.x,
                y=None
            )

        # Test a non-integer x value
        with pytest.raises(TypeError):
            dsa.DSAPrivateKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                x=None,
                y=DSA_KEY_1024.public_numbers.y
            )

    def test_invalid_dsa_public_key_arguments(self):
        # Test a modulus < 1024 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=2 ** 1000,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test a modulus < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=2 ** 2000,
                subgroup_order=DSA_KEY_2048.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_2048.public_numbers.parameter_numbers.g,
                y=DSA_KEY_2048.public_numbers.y
            )

        # Test a modulus < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=2 ** 3000,
                subgroup_order=DSA_KEY_3072.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                y=DSA_KEY_3072.public_numbers.y
            )

        # Test a modulus > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=2 ** 3100,
                subgroup_order=DSA_KEY_3072.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                y=DSA_KEY_3072.public_numbers.y
            )

        # Test a subgroup_order < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=2 ** 150,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test a subgroup_order < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=DSA_KEY_2048.public_numbers.parameter_numbers.p,
                subgroup_order=2 ** 250,
                generator=DSA_KEY_2048.public_numbers.parameter_numbers.g,
                y=DSA_KEY_2048.public_numbers.y
            )

        # Test a subgroup_order > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=DSA_KEY_3072.public_numbers.parameter_numbers.p,
                subgroup_order=2 ** 260,
                generator=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                y=DSA_KEY_3072.public_numbers.y
            )

        # Test a modulus, subgroup_order pair of (1024, 256) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_2048.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test a modulus, subgroup_order pair of (2048, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=DSA_KEY_2048.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_2048.public_numbers.parameter_numbers.g,
                y=DSA_KEY_2048.public_numbers.y
            )

        # Test a modulus, subgroup_order pair of (3072, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=DSA_KEY_3072.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                y=DSA_KEY_3072.public_numbers.y
            )

        # Test a generator < 1
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=0,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test a generator = 1
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=1,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test a generator > modulus
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=2 ** 1200,
                y=DSA_KEY_1024.public_numbers.y
            )

        # Test a non-integer y value
        with pytest.raises(TypeError):
            dsa.DSAPublicKey(
                modulus=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                subgroup_order=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                generator=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                y=None
            )


@pytest.mark.dsa
class TestDSAVerification(object):
    _algorithms_dict = {
        'SHA1': hashes.SHA1,
        'SHA224': hashes.SHA224,
        'SHA256': hashes.SHA256,
        'SHA384': hashes.SHA384,
        'SHA512': hashes.SHA512
    }

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join(
                "asymmetric", "DSA", "FIPS_186-3", "SigVer.rsp"),
            load_fips_dsa_sig_vectors
        )
    )
    def test_dsa_verification(self, vector, backend):
        digest_algorithm = vector['digest_algorithm'].replace("-", "")
        algorithm = self._algorithms_dict[digest_algorithm]
        if (
            not backend.dsa_parameters_supported(
                vector['p'], vector['q'], vector['g']
            ) or not backend.dsa_hash_supported(algorithm)
        ):
            pytest.skip(
                "{0} does not support the provided parameters".format(backend)
            )

        public_key = dsa.DSAPublicNumbers(
            parameter_numbers=dsa.DSAParameterNumbers(
                vector['p'], vector['q'], vector['g']
            ),
            y=vector['y']
        ).public_key(backend)
        sig = der_encode_dsa_signature(vector['r'], vector['s'])
        verifier = public_key.verifier(sig, algorithm())
        verifier.update(vector['msg'])
        if vector['result'] == "F":
            with pytest.raises(InvalidSignature):
                verifier.verify()
        else:
            verifier.verify()

    def test_dsa_verify_invalid_asn1(self, backend):
        parameters = dsa.DSAParameters.generate(1024, backend)
        private_key = dsa.DSAPrivateKey.generate(parameters, backend)
        public_key = private_key.public_key()
        verifier = public_key.verifier(b'fakesig', hashes.SHA1(), backend)
        verifier.update(b'fakesig')
        with pytest.raises(InvalidSignature):
            verifier.verify()

    def test_use_after_finalize(self, backend):
        parameters = dsa.DSAParameters.generate(1024, backend)
        private_key = dsa.DSAPrivateKey.generate(parameters, backend)
        public_key = private_key.public_key()
        verifier = public_key.verifier(b'fakesig', hashes.SHA1(), backend)
        verifier.update(b'irrelevant')
        with pytest.raises(InvalidSignature):
            verifier.verify()
        with pytest.raises(AlreadyFinalized):
            verifier.verify()
        with pytest.raises(AlreadyFinalized):
            verifier.update(b"more data")

    def test_dsa_verifier_invalid_backend(self, backend):
        pretend_backend = object()
        params = dsa.DSAParameters.generate(1024, backend)
        private_key = dsa.DSAPrivateKey.generate(params, backend)
        public_key = private_key.public_key()

        with raises_unsupported_algorithm(
                _Reasons.BACKEND_MISSING_INTERFACE):
            public_key.verifier(b"sig", hashes.SHA1(), pretend_backend)


@pytest.mark.dsa
class TestDSASignature(object):
    _algorithms_dict = {
        'SHA1': hashes.SHA1,
        'SHA224': hashes.SHA224,
        'SHA256': hashes.SHA256,
        'SHA384': hashes.SHA384,
        'SHA512': hashes.SHA512}

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join(
                "asymmetric", "DSA", "FIPS_186-3", "SigGen.txt"),
            load_fips_dsa_sig_vectors
        )
    )
    def test_dsa_signing(self, vector, backend):
        digest_algorithm = vector['digest_algorithm'].replace("-", "")
        algorithm = self._algorithms_dict[digest_algorithm]
        if (
            not backend.dsa_parameters_supported(
                vector['p'], vector['q'], vector['g']
            ) or not backend.dsa_hash_supported(algorithm)
        ):
            pytest.skip(
                "{0} does not support the provided parameters".format(backend)
            )

        private_key = dsa.DSAPrivateNumbers(
            public_numbers=dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    vector['p'], vector['q'], vector['g']
                ),
                y=vector['y']
            ),
            x=vector['x']
        ).private_key(backend)
        signer = private_key.signer(algorithm())
        signer.update(vector['msg'])
        signature = signer.finalize()
        assert signature

        public_key = private_key.public_key()
        verifier = public_key.verifier(signature, algorithm())
        verifier.update(vector['msg'])
        verifier.verify()

    def test_use_after_finalize(self, backend):
        parameters = dsa.DSAParameters.generate(1024, backend)
        private_key = dsa.DSAPrivateKey.generate(parameters, backend)
        signer = private_key.signer(hashes.SHA1(), backend)
        signer.update(b"data")
        signer.finalize()
        with pytest.raises(AlreadyFinalized):
            signer.finalize()
        with pytest.raises(AlreadyFinalized):
            signer.update(b"more data")

    def test_dsa_signer_invalid_backend(self, backend):
        pretend_backend = object()
        params = dsa.DSAParameters.generate(1024, backend)
        private_key = dsa.DSAPrivateKey.generate(params, backend)

        with raises_unsupported_algorithm(
                _Reasons.BACKEND_MISSING_INTERFACE):
            private_key.signer(hashes.SHA1(), pretend_backend)


def test_dsa_generate_invalid_backend():
    pretend_backend = object()

    with raises_unsupported_algorithm(
            _Reasons.BACKEND_MISSING_INTERFACE):
        dsa.DSAParameters.generate(1024, pretend_backend)

    pretend_parameters = object()
    with raises_unsupported_algorithm(
            _Reasons.BACKEND_MISSING_INTERFACE):
        dsa.DSAPrivateKey.generate(pretend_parameters, pretend_backend)


class TestDSANumbers(object):
    def test_dsa_parameter_numbers(self):
        parameter_numbers = dsa.DSAParameterNumbers(p=1, q=2, g=3)
        assert parameter_numbers.p == 1
        assert parameter_numbers.q == 2
        assert parameter_numbers.g == 3

    def test_dsa_parameter_numbers_invalid_types(self):
        with pytest.raises(TypeError):
            dsa.DSAParameterNumbers(p=None, q=2, g=3)

        with pytest.raises(TypeError):
            dsa.DSAParameterNumbers(p=1, q=None, g=3)

        with pytest.raises(TypeError):
            dsa.DSAParameterNumbers(p=1, q=2, g=None)

    def test_dsa_public_numbers(self):
        parameter_numbers = dsa.DSAParameterNumbers(p=1, q=2, g=3)
        public_numbers = dsa.DSAPublicNumbers(
            y=4,
            parameter_numbers=parameter_numbers
        )
        assert public_numbers.y == 4
        assert public_numbers.parameter_numbers == parameter_numbers

    def test_dsa_public_numbers_invalid_types(self):
        with pytest.raises(TypeError):
            dsa.DSAPublicNumbers(y=4, parameter_numbers=None)

        with pytest.raises(TypeError):
            parameter_numbers = dsa.DSAParameterNumbers(p=1, q=2, g=3)
            dsa.DSAPublicNumbers(y=None, parameter_numbers=parameter_numbers)

    def test_dsa_private_numbers(self):
        parameter_numbers = dsa.DSAParameterNumbers(p=1, q=2, g=3)
        public_numbers = dsa.DSAPublicNumbers(
            y=4,
            parameter_numbers=parameter_numbers
        )
        private_numbers = dsa.DSAPrivateNumbers(
            x=5,
            public_numbers=public_numbers
        )
        assert private_numbers.x == 5
        assert private_numbers.public_numbers == public_numbers

    def test_dsa_private_numbers_invalid_types(self):
        parameter_numbers = dsa.DSAParameterNumbers(p=1, q=2, g=3)
        public_numbers = dsa.DSAPublicNumbers(
            y=4,
            parameter_numbers=parameter_numbers
        )
        with pytest.raises(TypeError):
            dsa.DSAPrivateNumbers(x=4, public_numbers=None)

        with pytest.raises(TypeError):
            dsa.DSAPrivateNumbers(x=None, public_numbers=public_numbers)
