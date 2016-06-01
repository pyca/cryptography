# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

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

    def test_dh_parameters_supported(self, backend):
        assert backend.dh_parameters_supported(23, 5)
        assert not backend.dh_parameters_supported(23, 18)

    def test_convert_to_serialized(self, backend):
        parameters = backend.generate_dh_private_key_and_parameters(2, 512)

        private = parameters.private_numbers()

        p = private._public_numbers._parameter_numbers.p
        g = private._public_numbers._parameter_numbers.g

        params = dh.DHParameterNumbers(p, g)
        public = dh.DHPublicNumbers(1, params)
        private = dh.DHPrivateNumbers(2, public)

        serialized_params = params.parameters(backend)
        serialized_public = public.public_key(backend)
        serialized_private = private.private_key(backend)

        assert isinstance(serialized_params, dh.DHParametersWithSerialization)
        assert isinstance(serialized_public, dh.DHPublicKeyWithSerialization)
        assert isinstance(serialized_private, dh.DHPrivateKeyWithSerialization)

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

        if isinstance(parameters, dh.DHParametersWithSerialization):
            parameter_numbers = parameters.parameter_numbers()
            assert isinstance(parameter_numbers, dh.DHParameterNumbers)
            assert bit_length(parameter_numbers.p) == key_size

        if isinstance(public, dh.DHPublicKeyWithSerialization):
            assert isinstance(public.public_numbers(), dh.DHPublicNumbers)
            assert isinstance(public.parameters(), dh.DHParameters)

        if isinstance(key, dh.DHPrivateKeyWithSerialization):
            assert isinstance(key.private_numbers(), dh.DHPrivateNumbers)
            assert isinstance(key.parameters(), dh.DHParameters)

    def test_tls_exchange(self, backend):
        parameters = dh.generate_parameters(2, 512, backend)
        assert isinstance(parameters, dh.DHParameters)

        key1 = parameters.generate_private_key()
        key2 = parameters.generate_private_key()

        symkey1 = key1.exchange(key2.public_key())
        assert symkey1
        assert len(symkey1) == 512 // 8

        symkey2 = key2.exchange(key1.public_key())
        assert symkey1 == symkey2

    def test_bad_tls_exchange(self, backend):
        parameters1 = dh.generate_parameters(2, 512, backend)
        key1 = parameters1.generate_private_key()
        pub_key1 = key1.public_key()

        parameters2 = dh.generate_parameters(2, 512, backend)
        key2 = parameters2.generate_private_key()
        pub_key2 = key2.public_key()

        if pub_key2.public_numbers().y >= parameters1.parameter_numbers().p:
            with pytest.raises(ValueError):
                key1.exchange(pub_key2)
        elif pub_key1.public_numbers().y >= parameters2.parameter_numbers().p:
            with pytest.raises(ValueError):
                key2.exchange(pub_key1)
        else:
            symkey1 = key1.exchange(pub_key2)
            assert symkey1

            symkey2 = key2.exchange(pub_key1)

            assert symkey1 != symkey2
