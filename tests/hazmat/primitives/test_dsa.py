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

from cryptography.exceptions import AlreadyFinalized, InvalidSignature
from cryptography.hazmat.backends.interfaces import DSABackend
from cryptography.hazmat.primitives import hashes, interfaces
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.utils import bit_length

from .fixtures_dsa import (
    DSA_KEY_1024, DSA_KEY_2048, DSA_KEY_3072
)
from ...utils import (
    der_encode_dsa_signature, load_fips_dsa_key_pair_vectors,
    load_fips_dsa_sig_vectors, load_vectors_from_file,
)


@pytest.mark.requires_backend_interface(interface=DSABackend)
class TestDSA(object):
    def test_generate_dsa_parameters(self, backend):
        parameters = dsa.generate_parameters(1024, backend)
        assert isinstance(parameters, interfaces.DSAParameters)

    def test_generate_invalid_dsa_parameters(self, backend):
        with pytest.raises(ValueError):
            dsa.generate_parameters(1, backend)

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
        skey = parameters.generate_private_key()
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

    def test_generate_dsa_private_key_and_parameters(self, backend):
        skey = dsa.generate_private_key(1024, backend)
        assert skey
        if isinstance(skey, interfaces.DSAPrivateKeyWithNumbers):
            numbers = skey.private_numbers()
            skey_parameters = numbers.public_numbers.parameter_numbers
            assert numbers.public_numbers.y == pow(
                skey_parameters.g, numbers.x, skey_parameters.p
            )

    def test_invalid_parameters_values(self, backend):
        # Test a p < 1024 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameterNumbers(
                p=2 ** 1000,
                q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
            ).parameters(backend)

        # Test a p < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameterNumbers(
                p=2 ** 2000,
                q=DSA_KEY_2048.public_numbers.parameter_numbers.q,
                g=DSA_KEY_2048.public_numbers.parameter_numbers.g,
            ).parameters(backend)

        # Test a p < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameterNumbers(
                p=2 ** 3000,
                q=DSA_KEY_3072.public_numbers.parameter_numbers.q,
                g=DSA_KEY_3072.public_numbers.parameter_numbers.g,
            ).parameters(backend)

        # Test a p > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameterNumbers(
                p=2 ** 3100,
                q=DSA_KEY_3072.public_numbers.parameter_numbers.q,
                g=DSA_KEY_3072.public_numbers.parameter_numbers.g,
            ).parameters(backend)

        # Test a q < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameterNumbers(
                p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                q=2 ** 150,
                g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
            ).parameters(backend)

        # Test a q < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameterNumbers(
                p=DSA_KEY_2048.public_numbers.parameter_numbers.p,
                q=2 ** 250,
                g=DSA_KEY_2048.public_numbers.parameter_numbers.g
            ).parameters(backend)

        # Test a q > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameterNumbers(
                p=DSA_KEY_3072.public_numbers.parameter_numbers.p,
                q=2 ** 260,
                g=DSA_KEY_3072.public_numbers.parameter_numbers.g,
            ).parameters(backend)

        # Test a g < 1
        with pytest.raises(ValueError):
            dsa.DSAParameterNumbers(
                p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                g=0
            ).parameters(backend)

        # Test a g = 1
        with pytest.raises(ValueError):
            dsa.DSAParameterNumbers(
                p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                g=1
            ).parameters(backend)

        # Test a g > p
        with pytest.raises(ValueError):
            dsa.DSAParameterNumbers(
                p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                g=2 ** 1200
            ).parameters(backend)

    def test_invalid_dsa_private_key_arguments(self, backend):
        # Test a p < 1024 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=2 ** 1000,
                        q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                        g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                    ),
                    y=DSA_KEY_1024.public_numbers.y
                ),
                x=DSA_KEY_1024.x
            ).private_key(backend)

        # Test a p < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=2 ** 2000,
                        q=DSA_KEY_2048.public_numbers.parameter_numbers.q,
                        g=DSA_KEY_2048.public_numbers.parameter_numbers.g,
                    ),
                    y=DSA_KEY_2048.public_numbers.y
                ),
                x=DSA_KEY_2048.x,
            ).private_key(backend)

        # Test a p < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=2 ** 3000,
                        q=DSA_KEY_3072.public_numbers.parameter_numbers.q,
                        g=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                    ),
                    y=DSA_KEY_3072.public_numbers.y
                ),
                x=DSA_KEY_3072.x,
            ).private_key(backend)

        # Test a p > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=2 ** 3100,
                        q=DSA_KEY_3072.public_numbers.parameter_numbers.q,
                        g=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                    ),
                    y=DSA_KEY_3072.public_numbers.y
                ),
                x=DSA_KEY_3072.x,
            ).private_key(backend)

        # Test a q < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                        q=2 ** 150,
                        g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                    ),
                    y=DSA_KEY_1024.public_numbers.y
                ),
                x=DSA_KEY_1024.x,
            ).private_key(backend)

        # Test a q < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_2048.public_numbers.parameter_numbers.p,
                        q=2 ** 250,
                        g=DSA_KEY_2048.public_numbers.parameter_numbers.g,
                    ),
                    y=DSA_KEY_2048.public_numbers.y
                ),
                x=DSA_KEY_2048.x,
            ).private_key(backend)

        # Test a q > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_3072.public_numbers.parameter_numbers.p,
                        q=2 ** 260,
                        g=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                    ),
                    y=DSA_KEY_3072.public_numbers.y
                ),
                x=DSA_KEY_3072.x,
            ).private_key(backend)

        # Test a g < 1
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                        q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                        g=0,
                    ),
                    y=DSA_KEY_1024.public_numbers.y
                ),
                x=DSA_KEY_1024.x,
            ).private_key(backend)

        # Test a g = 1
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                        q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                        g=1,
                    ),
                    y=DSA_KEY_1024.public_numbers.y
                ),
                x=DSA_KEY_1024.x,
            ).private_key(backend)

        # Test a g > p
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                        q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                        g=2 ** 1200,
                    ),
                    y=DSA_KEY_1024.public_numbers.y
                ),
                x=DSA_KEY_1024.x,
            ).private_key(backend)

        # Test x = 0
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                        q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                        g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                    ),
                    y=DSA_KEY_1024.public_numbers.y
                ),
                x=0,
            ).private_key(backend)

        # Test x < 0
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                        q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                        g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                    ),
                    y=DSA_KEY_1024.public_numbers.y
                ),
                x=-2,
            ).private_key(backend)

        # Test x = q
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                        q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                        g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                    ),
                    y=DSA_KEY_1024.public_numbers.y
                ),
                x=2 ** 159,
            ).private_key(backend)

        # Test x > q
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                        q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                        g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                    ),
                    y=DSA_KEY_1024.public_numbers.y
                ),
                x=2 ** 200,
            ).private_key(backend)

        # Test y != (g ** x) % p
        with pytest.raises(ValueError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                        q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                        g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                    ),
                    y=2 ** 100
                ),
                x=DSA_KEY_1024.x,
            ).private_key(backend)

        # Test a non-integer y value
        with pytest.raises(TypeError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                        q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                        g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                    ),
                    y=None
                ),
                x=DSA_KEY_1024.x,
            ).private_key(backend)

        # Test a non-integer x value
        with pytest.raises(TypeError):
            dsa.DSAPrivateNumbers(
                public_numbers=dsa.DSAPublicNumbers(
                    parameter_numbers=dsa.DSAParameterNumbers(
                        p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                        q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                        g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                    ),
                    y=DSA_KEY_1024.public_numbers.y
                ),
                x=None,
            ).private_key(backend)

    def test_invalid_dsa_public_key_arguments(self, backend):
        # Test a p < 1024 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    p=2 ** 1000,
                    q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                    g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                ),
                y=DSA_KEY_1024.public_numbers.y
            ).public_key(backend)

        # Test a p < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    p=2 ** 2000,
                    q=DSA_KEY_2048.public_numbers.parameter_numbers.q,
                    g=DSA_KEY_2048.public_numbers.parameter_numbers.g,
                ),
                y=DSA_KEY_2048.public_numbers.y
            ).public_key(backend)

        # Test a p < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    p=2 ** 3000,
                    q=DSA_KEY_3072.public_numbers.parameter_numbers.q,
                    g=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                ),
                y=DSA_KEY_3072.public_numbers.y
            ).public_key(backend)

        # Test a p > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    p=2 ** 3100,
                    q=DSA_KEY_3072.public_numbers.parameter_numbers.q,
                    g=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                ),
                y=DSA_KEY_3072.public_numbers.y
            ).public_key(backend)

        # Test a q < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                    q=2 ** 150,
                    g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                ),
                y=DSA_KEY_1024.public_numbers.y
            ).public_key(backend)

        # Test a q < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    p=DSA_KEY_2048.public_numbers.parameter_numbers.p,
                    q=2 ** 250,
                    g=DSA_KEY_2048.public_numbers.parameter_numbers.g,
                ),
                y=DSA_KEY_2048.public_numbers.y
            ).public_key(backend)

        # Test a q > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    p=DSA_KEY_3072.public_numbers.parameter_numbers.p,
                    q=2 ** 260,
                    g=DSA_KEY_3072.public_numbers.parameter_numbers.g,
                ),
                y=DSA_KEY_3072.public_numbers.y
            ).public_key(backend)

        # Test a g < 1
        with pytest.raises(ValueError):
            dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                    q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                    g=0,
                ),
                y=DSA_KEY_1024.public_numbers.y
            ).public_key(backend)

        # Test a g = 1
        with pytest.raises(ValueError):
            dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                    q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                    g=1,
                ),
                y=DSA_KEY_1024.public_numbers.y
            ).public_key(backend)

        # Test a g > p
        with pytest.raises(ValueError):
            dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                    q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                    g=2 ** 1200,
                ),
                y=DSA_KEY_1024.public_numbers.y
            ).public_key(backend)

        # Test a non-integer y value
        with pytest.raises(TypeError):
            dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    p=DSA_KEY_1024.public_numbers.parameter_numbers.p,
                    q=DSA_KEY_1024.public_numbers.parameter_numbers.q,
                    g=DSA_KEY_1024.public_numbers.parameter_numbers.g,
                ),
                y=None
            ).public_key(backend)


@pytest.mark.requires_backend_interface(interface=DSABackend)
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
        public_key = DSA_KEY_1024.public_numbers.public_key(backend)
        verifier = public_key.verifier(b'fakesig', hashes.SHA1())
        verifier.update(b'fakesig')
        with pytest.raises(InvalidSignature):
            verifier.verify()

    def test_use_after_finalize(self, backend):
        public_key = DSA_KEY_1024.public_numbers.public_key(backend)
        verifier = public_key.verifier(b'fakesig', hashes.SHA1())
        verifier.update(b'irrelevant')
        with pytest.raises(InvalidSignature):
            verifier.verify()
        with pytest.raises(AlreadyFinalized):
            verifier.verify()
        with pytest.raises(AlreadyFinalized):
            verifier.update(b"more data")


@pytest.mark.requires_backend_interface(interface=DSABackend)
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
        private_key = DSA_KEY_1024.private_key(backend)
        signer = private_key.signer(hashes.SHA1())
        signer.update(b"data")
        signer.finalize()
        with pytest.raises(AlreadyFinalized):
            signer.finalize()
        with pytest.raises(AlreadyFinalized):
            signer.update(b"more data")


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
