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

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import interfaces


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
    def test_generate_dh(self, backend):
        parameters = dh.generate_parameters(2, 512, backend)
        assert isinstance(parameters, interfaces.DHParameters)

        key = parameters.generate_private_key()
        assert isinstance(key, interfaces.DHPrivateKey)
        assert key.key_size == 512

        public = key.public_key()
        assert isinstance(public, interfaces.DHPublicKey)
        assert public.key_size == 512

    def test_tls_exchange(self, backend):
        parameters = dh.generate_parameters(2, 512, backend)
        assert isinstance(parameters, interfaces.DHParameters)

        key1 = parameters.generate_private_key()
        key2 = parameters.generate_private_key()

        exch = key1.exchange(dh.TLSKeyExchange())
        symkey1 = exch.agree(key2.public_key().public_numbers.public_value)
        assert symkey1
        assert len(symkey1) == 512//8

        exch = key2.exchange(dh.TLSKeyExchange())
        symkey2 = exch.agree(key1.public_key().public_numbers.public_value)
        assert symkey1 == symkey2

    def test_bad_tls_exchange(self, backend):
        parameters = dh.generate_parameters(2, 512, backend)
        assert isinstance(parameters, interfaces.DHParameters)

        key1 = parameters.generate_private_key()

        exch = key1.exchange(dh.TLSKeyExchange())

        with pytest.raises(ValueError):
            exch.agree(1)
