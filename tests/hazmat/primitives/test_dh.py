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

from cryptography import utils
from cryptography.exceptions import _Reasons
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.utils import bit_length

from ...utils import (
    load_kasvs_dh_vectors, load_vectors_from_file,
    raises_unsupported_algorithm
)


@utils.register_interface(interfaces.DHExchangeAlgorithm)
class DummyKeyExchange(object):
    pass


def test_dh_parameters():
    params = dh.DHParameterNumbers(
        65537, 3
    )

    assert params.modulus == 65537
    assert params.generator == 3

    with pytest.raises(TypeError):
        dh.DHParameterNumbers(
            None, 3
        )

    with pytest.raises(TypeError):
        dh.DHParameterNumbers(
            65537, None
        )

    with pytest.raises(TypeError):
        dh.DHParameterNumbers(
            None, None
        )


def test_dh_numbers():
    params = dh.DHParameterNumbers(
        65537, 3
    )

    public = dh.DHPublicNumbers(
        params, 1
    )

    assert public.parameter_numbers is params
    assert public.public_value == 1

    with pytest.raises(TypeError):
        dh.DHPublicNumbers(
            None, 1
        )

    with pytest.raises(TypeError):
        dh.DHPublicNumbers(
            params, None
        )

    private = dh.DHPrivateNumbers(
        public, 1
    )

    assert private.public_numbers is public
    assert private.private_value == 1

    with pytest.raises(TypeError):
        dh.DHPrivateNumbers(
            None, 1
        )

    with pytest.raises(TypeError):
        dh.DHPrivateNumbers(
            public, None
        )


@pytest.mark.dh
class TestDH(object):
    def test_small_key_generate_dh(self, backend):
        with pytest.raises(ValueError):
            dh.generate_parameters(2, 511, backend)

    def test_generate_dh(self, backend):
        generator = 2
        key_size = 512

        parameters = dh.generate_parameters(generator, key_size, backend)
        assert isinstance(parameters, interfaces.DHParameters)

        key = parameters.generate_private_key()
        assert isinstance(key, interfaces.DHPrivateKey)
        assert key.key_size == key_size

        public = key.public_key()
        assert isinstance(public, interfaces.DHPublicKey)
        assert public.key_size == key_size

        if isinstance(parameters, interfaces.DHParametersWithNumbers):
            parameter_numbers = parameters.parameter_numbers
            assert isinstance(parameter_numbers, dh.DHParameterNumbers)
            assert bit_length(parameter_numbers.modulus) == key_size

        if isinstance(public, interfaces.DHPublicKeyWithNumbers):
            assert isinstance(public.public_numbers, dh.DHPublicNumbers)

        if isinstance(key, interfaces.DHPrivateKeyWithNumbers):
            assert isinstance(key.private_numbers, dh.DHPrivateNumbers)

    def test_tls_exchange(self, backend):
        parameters = dh.generate_parameters(2, 512, backend)
        assert isinstance(parameters, interfaces.DHParameters)

        key1 = parameters.generate_private_key()
        key2 = parameters.generate_private_key()

        exch = key1.exchange(dh.TLSKeyExchange())
        symkey1 = exch.agree(key2.public_key().public_numbers.public_value)
        assert symkey1
        assert len(symkey1) == 512 // 8

        exch = key2.exchange(dh.TLSKeyExchange())
        symkey2 = exch.agree(key1.public_key().public_numbers.public_value)
        assert symkey1 == symkey2

    def test_bad_tls_exchange(self, backend):
        parameters = dh.generate_parameters(2, 512, backend)
        key1 = parameters.generate_private_key()

        exch = key1.exchange(dh.TLSKeyExchange())

        with pytest.raises(ValueError):
            exch.agree(1)

    def test_unsupported_agreement(self, backend):
        parameters = dh.generate_parameters(2, 512, backend)
        key1 = parameters.generate_private_key()

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_KEY_EXCHANGE):
            key1.exchange(DummyKeyExchange())

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("asymmetric", "DH",
                         "KASValidityTest_FFCStatic_NOKC_ZZOnly_init.fax"),
            load_kasvs_dh_vectors
        )
    )
    def test_kasvs_generate_private_key(self, vector, backend):
        parameter_numbers = dh.DHParameterNumbers(
            modulus=vector['p'],
            generator=vector['g']
        )

        parameters = parameter_numbers.parameters(backend)
        key = parameters.generate_private_key()
        assert isinstance(key, interfaces.DHPrivateKey)

        key_params = key.parameters()

        if isinstance(key_params, interfaces.DHParametersWithNumbers):
            key_param_numbers = key_params.parameter_numbers
            assert key_param_numbers.modulus == parameter_numbers.modulus
            assert key_param_numbers.generator == parameter_numbers.generator

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("asymmetric", "DH",
                         "KASValidityTest_FFCStatic_NOKC_ZZOnly_init.fax"),
            load_kasvs_dh_vectors
        )
    )
    def test_kasvs_agree_key(self, vector, backend):
        parameters = dh.DHParameterNumbers(
            modulus=vector['p'],
            generator=vector['g']
        )

        pubnum1 = dh.DHPublicNumbers(
            parameters,
            vector['y1']
        )

        privnum1 = dh.DHPrivateNumbers(
            pubnum1,
            vector['x1']
        )

        pubnum2 = dh.DHPublicNumbers(
            parameters,
            vector['y2']
        )

        privnum2 = dh.DHPrivateNumbers(
            pubnum2,
            vector['x2']
        )

        key1 = privnum1.private_key(backend)
        key2 = privnum2.private_key(backend)

        pubkey1 = pubnum1.public_key(backend)
        pubkey2 = pubnum2.public_key(backend)

        exch1 = key1.exchange(dh.TLSKeyExchange())
        agreed_key1 = exch1.agree(
            pubkey2.public_numbers.public_value
        )
        assert agreed_key1

        exch2 = key2.exchange(dh.TLSKeyExchange())
        agreed_key2 = exch2.agree(
            pubkey1.public_numbers.public_value
        )
        assert agreed_key2

        fail = False

        if vector['fail_z']:
            assert agreed_key1 != vector['z']
            assert agreed_key2 != vector['z']
            fail = True

        if vector['fail_agree']:
            assert agreed_key1 != agreed_key2
            fail = True

        if fail is False:
            assert agreed_key1 == vector['z']
            assert agreed_key1 == agreed_key2
