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

import pytest

from cryptography.hazmat.backends.interfaces import DHBackend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.utils import bit_length


def test_dh_parameternumbers():
    params = dh.DHParameterNumbers(
        65537, 3
    )

    assert params.p == 65537
    assert params.g == 3

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
        1, params
    )

    assert public.parameter_numbers is params
    assert public.y == 1

    with pytest.raises(TypeError):
        dh.DHPublicNumbers(
            1, None
        )

    with pytest.raises(TypeError):
        dh.DHPublicNumbers(
            None, params
        )

    private = dh.DHPrivateNumbers(
        1, public
    )

    assert private.public_numbers is public
    assert private.x == 1

    with pytest.raises(TypeError):
        dh.DHPrivateNumbers(
            1, None
        )

    with pytest.raises(TypeError):
        dh.DHPrivateNumbers(
            None, public
        )


def test_dh_parameter_numbers_equality():
    assert dh.DHParameterNumbers(65537, 3) == dh.DHParameterNumbers(65537, 3)
    assert dh.DHParameterNumbers(6, 3) != dh.DHParameterNumbers(65537, 3)
    assert dh.DHParameterNumbers(65537, 0) != dh.DHParameterNumbers(65537, 3)
    assert dh.DHParameterNumbers(65537, 0) != object()


def test_dh_private_numbers_equality():
    params = dh.DHParameterNumbers(65537, 3)
    public = dh.DHPublicNumbers(1, params)
    private = dh.DHPrivateNumbers(2, public)

    assert private == dh.DHPrivateNumbers(2, public)
    assert private != dh.DHPrivateNumbers(0, public)
    assert private != dh.DHPrivateNumbers(2, dh.DHPublicNumbers(0, params))
    assert private != dh.DHPrivateNumbers(
        2, dh.DHPublicNumbers(1, dh.DHParameterNumbers(65537, 0))
    )
    assert private != object()


def test_dh_public_numbers_equality():
    params = dh.DHParameterNumbers(65537, 3)
    public = dh.DHPublicNumbers(1, params)

    assert public == dh.DHPublicNumbers(1, params)
    assert public != dh.DHPublicNumbers(0, params)
    assert public != dh.DHPublicNumbers(1, dh.DHParameterNumbers(65537, 0))
    assert public != object()


@pytest.mark.requires_backend_interface(interface=DHBackend)
class TestDH(object):
    def test_small_key_generate_dh(self, backend):
        with pytest.raises(ValueError):
            dh.generate_parameters(2, 511, backend)

    def test_generate_dh(self, backend):
        generator = 2
        key_size = 512

        parameters = dh.generate_parameters(generator, key_size, backend)
        assert isinstance(parameters, dh.DHParameters)

        key = parameters.generate_private_key()
        assert isinstance(key, dh.DHPrivateKey)
        assert key.key_size == key_size

        public = key.public_key()
        assert isinstance(public, dh.DHPublicKey)
        assert public.key_size == key_size

        if isinstance(parameters, dh.DHParametersWithNumbers):
            parameter_numbers = parameters.parameter_numbers()
            assert isinstance(parameter_numbers, dh.DHParameterNumbers)
            assert bit_length(parameter_numbers.p) == key_size

        if isinstance(public, dh.DHPublicKeyWithNumbers):
            assert isinstance(public.public_numbers(), dh.DHPublicNumbers)
            assert isinstance(public.parameters(), dh.DHParameters)

        if isinstance(key, dh.DHPrivateKeyWithNumbers):
            assert isinstance(key.private_numbers(), dh.DHPrivateNumbers)
            assert isinstance(key.parameters(), dh.DHParameters)

    def test_tls_exchange(self, backend):
        parameters = dh.generate_parameters(2, 512, backend)
        assert isinstance(parameters, dh.DHParameters)

        key1 = parameters.generate_private_key()
        key2 = parameters.generate_private_key()

        exch = key1.exchange()
        symkey1 = exch.agree(key2.public_key().public_numbers().y)
        assert symkey1
        assert len(symkey1) == 512 // 8

        exch = key2.exchange()
        symkey2 = exch.agree(key1.public_key().public_numbers().y)
        assert symkey1 == symkey2

    def test_bad_tls_exchange(self, backend):
        parameters = dh.generate_parameters(2, 512, backend)
        key1 = parameters.generate_private_key()

        exch = key1.exchange()

        with pytest.raises(ValueError):
            exch.agree(1)
