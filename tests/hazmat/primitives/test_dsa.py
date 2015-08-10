# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import itertools
import os

import pytest

from cryptography import utils
from cryptography.exceptions import AlreadyFinalized, InvalidSignature
from cryptography.hazmat.backends.interfaces import (
    DSABackend, PEMSerializationBackend
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature
)
from cryptography.utils import bit_length

from .fixtures_dsa import (
    DSA_KEY_1024, DSA_KEY_2048, DSA_KEY_3072
)
from ...utils import (
    load_fips_dsa_key_pair_vectors, load_fips_dsa_sig_vectors,
    load_vectors_from_file,
)


@utils.register_interface(serialization.KeySerializationEncryption)
class DummyKeyEncryption(object):
    pass


@pytest.mark.requires_backend_interface(interface=DSABackend)
class TestDSA(object):
    def test_generate_dsa_parameters(self, backend):
        parameters = dsa.generate_parameters(1024, backend)
        assert isinstance(parameters, dsa.DSAParameters)

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
        sig = encode_dss_signature(vector['r'], vector['s'])
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


class TestDSANumberEquality(object):
    def test_parameter_numbers_eq(self):
        param = dsa.DSAParameterNumbers(1, 2, 3)
        assert param == dsa.DSAParameterNumbers(1, 2, 3)

    def test_parameter_numbers_ne(self):
        param = dsa.DSAParameterNumbers(1, 2, 3)
        assert param != dsa.DSAParameterNumbers(1, 2, 4)
        assert param != dsa.DSAParameterNumbers(1, 1, 3)
        assert param != dsa.DSAParameterNumbers(2, 2, 3)
        assert param != object()

    def test_public_numbers_eq(self):
        pub = dsa.DSAPublicNumbers(1, dsa.DSAParameterNumbers(1, 2, 3))
        assert pub == dsa.DSAPublicNumbers(1, dsa.DSAParameterNumbers(1, 2, 3))

    def test_public_numbers_ne(self):
        pub = dsa.DSAPublicNumbers(1, dsa.DSAParameterNumbers(1, 2, 3))
        assert pub != dsa.DSAPublicNumbers(2, dsa.DSAParameterNumbers(1, 2, 3))
        assert pub != dsa.DSAPublicNumbers(1, dsa.DSAParameterNumbers(2, 2, 3))
        assert pub != dsa.DSAPublicNumbers(1, dsa.DSAParameterNumbers(1, 3, 3))
        assert pub != dsa.DSAPublicNumbers(1, dsa.DSAParameterNumbers(1, 2, 4))
        assert pub != object()

    def test_private_numbers_eq(self):
        pub = dsa.DSAPublicNumbers(1, dsa.DSAParameterNumbers(1, 2, 3))
        priv = dsa.DSAPrivateNumbers(1, pub)
        assert priv == dsa.DSAPrivateNumbers(
            1, dsa.DSAPublicNumbers(
                1, dsa.DSAParameterNumbers(1, 2, 3)
            )
        )

    def test_private_numbers_ne(self):
        pub = dsa.DSAPublicNumbers(1, dsa.DSAParameterNumbers(1, 2, 3))
        priv = dsa.DSAPrivateNumbers(1, pub)
        assert priv != dsa.DSAPrivateNumbers(
            2, dsa.DSAPublicNumbers(
                1, dsa.DSAParameterNumbers(1, 2, 3)
            )
        )
        assert priv != dsa.DSAPrivateNumbers(
            1, dsa.DSAPublicNumbers(
                2, dsa.DSAParameterNumbers(1, 2, 3)
            )
        )
        assert priv != dsa.DSAPrivateNumbers(
            1, dsa.DSAPublicNumbers(
                1, dsa.DSAParameterNumbers(2, 2, 3)
            )
        )
        assert priv != dsa.DSAPrivateNumbers(
            1, dsa.DSAPublicNumbers(
                1, dsa.DSAParameterNumbers(1, 3, 3)
            )
        )
        assert priv != dsa.DSAPrivateNumbers(
            1, dsa.DSAPublicNumbers(
                1, dsa.DSAParameterNumbers(1, 2, 4)
            )
        )
        assert priv != object()


@pytest.mark.requires_backend_interface(interface=DSABackend)
@pytest.mark.requires_backend_interface(interface=PEMSerializationBackend)
class TestDSASerialization(object):
    @pytest.mark.parametrize(
        ("fmt", "password"),
        itertools.product(
            [
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.PrivateFormat.PKCS8
            ],
            [
                b"s",
                b"longerpassword",
                b"!*$&(@#$*&($T@%_somesymbols",
                b"\x01" * 1000,
            ]
        )
    )
    def test_private_bytes_encrypted_pem(self, backend, fmt, password):
        key_bytes = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "unenc-dsa-pkcs8.pem"),
            lambda pemfile: pemfile.read().encode()
        )
        key = serialization.load_pem_private_key(key_bytes, None, backend)
        serialized = key.private_bytes(
            serialization.Encoding.PEM,
            fmt,
            serialization.BestAvailableEncryption(password)
        )
        loaded_key = serialization.load_pem_private_key(
            serialized, password, backend
        )
        loaded_priv_num = loaded_key.private_numbers()
        priv_num = key.private_numbers()
        assert loaded_priv_num == priv_num

    @pytest.mark.parametrize(
        ("fmt", "password"),
        [
            [serialization.PrivateFormat.PKCS8, b"s"],
            [serialization.PrivateFormat.PKCS8, b"longerpassword"],
            [serialization.PrivateFormat.PKCS8, b"!*$&(@#$*&($T@%_somesymbol"],
            [serialization.PrivateFormat.PKCS8, b"\x01" * 1000]
        ]
    )
    def test_private_bytes_encrypted_der(self, backend, fmt, password):
        key_bytes = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "unenc-dsa-pkcs8.pem"),
            lambda pemfile: pemfile.read().encode()
        )
        key = serialization.load_pem_private_key(key_bytes, None, backend)
        serialized = key.private_bytes(
            serialization.Encoding.DER,
            fmt,
            serialization.BestAvailableEncryption(password)
        )
        loaded_key = serialization.load_der_private_key(
            serialized, password, backend
        )
        loaded_priv_num = loaded_key.private_numbers()
        priv_num = key.private_numbers()
        assert loaded_priv_num == priv_num

    @pytest.mark.parametrize(
        ("encoding", "fmt", "loader_func"),
        [
            [
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.load_pem_private_key
            ],
            [
                serialization.Encoding.DER,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.load_der_private_key
            ],
            [
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.load_pem_private_key
            ],
            [
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.load_der_private_key
            ],
        ]
    )
    def test_private_bytes_unencrypted(self, backend, encoding, fmt,
                                       loader_func):
        key = DSA_KEY_1024.private_key(backend)
        serialized = key.private_bytes(
            encoding, fmt, serialization.NoEncryption()
        )
        loaded_key = loader_func(serialized, None, backend)
        loaded_priv_num = loaded_key.private_numbers()
        priv_num = key.private_numbers()
        assert loaded_priv_num == priv_num

    @pytest.mark.parametrize(
        ("key_path", "encoding", "loader_func"),
        [
            [
                os.path.join(
                    "asymmetric",
                    "Traditional_OpenSSL_Serialization",
                    "dsa.1024.pem"
                ),
                serialization.Encoding.PEM,
                serialization.load_pem_private_key
            ],
            [
                os.path.join(
                    "asymmetric", "DER_Serialization", "dsa.1024.der"
                ),
                serialization.Encoding.DER,
                serialization.load_der_private_key
            ],
        ]
    )
    def test_private_bytes_traditional_openssl_unencrypted(
        self, backend, key_path, encoding, loader_func
    ):
        key_bytes = load_vectors_from_file(
            key_path, lambda pemfile: pemfile.read(), mode="rb"
        )
        key = loader_func(key_bytes, None, backend)
        serialized = key.private_bytes(
            encoding,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
        assert serialized == key_bytes

    def test_private_bytes_traditional_der_encrypted_invalid(self, backend):
        key = DSA_KEY_1024.private_key(backend)
        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.BestAvailableEncryption(b"password")
            )

    def test_private_bytes_invalid_encoding(self, backend):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "unenc-dsa-pkcs8.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )
        with pytest.raises(TypeError):
            key.private_bytes(
                "notencoding",
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )

    def test_private_bytes_invalid_format(self, backend):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "unenc-dsa-pkcs8.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )
        with pytest.raises(TypeError):
            key.private_bytes(
                serialization.Encoding.PEM,
                "invalidformat",
                serialization.NoEncryption()
            )

    def test_private_bytes_invalid_encryption_algorithm(self, backend):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "unenc-dsa-pkcs8.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )
        with pytest.raises(TypeError):
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                "notanencalg"
            )

    def test_private_bytes_unsupported_encryption_type(self, backend):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "unenc-dsa-pkcs8.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )
        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                DummyKeyEncryption()
            )


@pytest.mark.requires_backend_interface(interface=DSABackend)
@pytest.mark.requires_backend_interface(interface=PEMSerializationBackend)
class TestDSAPEMPublicKeySerialization(object):
    @pytest.mark.parametrize(
        ("key_path", "loader_func", "encoding"),
        [
            (
                os.path.join("asymmetric", "PKCS8", "unenc-dsa-pkcs8.pub.pem"),
                serialization.load_pem_public_key,
                serialization.Encoding.PEM,
            ), (
                os.path.join(
                    "asymmetric",
                    "DER_Serialization",
                    "unenc-dsa-pkcs8.pub.der"
                ),
                serialization.load_der_public_key,
                serialization.Encoding.DER,
            )
        ]
    )
    def test_public_bytes_match(self, key_path, loader_func, encoding,
                                backend):
        key_bytes = load_vectors_from_file(
            key_path, lambda pemfile: pemfile.read(), mode="rb"
        )
        key = loader_func(key_bytes, backend)
        serialized = key.public_bytes(
            encoding, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert serialized == key_bytes

    def test_public_bytes_invalid_encoding(self, backend):
        key = DSA_KEY_2048.private_key(backend).public_key()
        with pytest.raises(TypeError):
            key.public_bytes(
                "notencoding",
                serialization.PublicFormat.SubjectPublicKeyInfo
            )

    def test_public_bytes_invalid_format(self, backend):
        key = DSA_KEY_2048.private_key(backend).public_key()
        with pytest.raises(TypeError):
            key.public_bytes(serialization.Encoding.PEM, "invalidformat")

    def test_public_bytes_pkcs1_unsupported(self, backend):
        key = DSA_KEY_2048.private_key(backend).public_key()
        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
            )
