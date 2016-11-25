# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

import pytest

from cryptography.hazmat.backends.interfaces import DHBackend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.utils import bit_length, int_from_bytes
from ...utils import load_nist_vectors, load_vectors_from_file


def test_dh_parameternumbers():
    params = dh.DHParameterNumbers(
        65537, 2
    )

    assert params.p == 65537
    assert params.g == 2

    with pytest.raises(TypeError):
        dh.DHParameterNumbers(
            None, 2
        )

    with pytest.raises(TypeError):
        dh.DHParameterNumbers(
            65537, None
        )

    with pytest.raises(TypeError):
        dh.DHParameterNumbers(
            None, None
        )

    with pytest.raises(ValueError):
        dh.DHParameterNumbers(
            65537, 7
        )


def test_dh_numbers():
    params = dh.DHParameterNumbers(
        65537, 2
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
    assert dh.DHParameterNumbers(65537, 2) == dh.DHParameterNumbers(65537, 2)
    assert dh.DHParameterNumbers(6, 2) != dh.DHParameterNumbers(65537, 2)
    assert dh.DHParameterNumbers(65537, 5) != dh.DHParameterNumbers(65537, 2)
    assert dh.DHParameterNumbers(65537, 2) != object()


def test_dh_private_numbers_equality():
    params = dh.DHParameterNumbers(65537, 2)
    public = dh.DHPublicNumbers(1, params)
    private = dh.DHPrivateNumbers(2, public)

    assert private == dh.DHPrivateNumbers(2, public)
    assert private != dh.DHPrivateNumbers(0, public)
    assert private != dh.DHPrivateNumbers(2, dh.DHPublicNumbers(0, params))
    assert private != dh.DHPrivateNumbers(
        2, dh.DHPublicNumbers(1, dh.DHParameterNumbers(65537, 5))
    )
    assert private != object()


def test_dh_public_numbers_equality():
    params = dh.DHParameterNumbers(65537, 2)
    public = dh.DHPublicNumbers(1, params)

    assert public == dh.DHPublicNumbers(1, params)
    assert public != dh.DHPublicNumbers(0, params)
    assert public != dh.DHPublicNumbers(1, dh.DHParameterNumbers(65537, 5))
    assert public != object()


@pytest.mark.requires_backend_interface(interface=DHBackend)
class TestDH(object):
    def test_small_key_generate_dh(self, backend):
        with pytest.raises(ValueError):
            dh.generate_parameters(2, 511, backend)

    def test_unsupported_generator_generate_dh(self, backend):
        with pytest.raises(ValueError):
            dh.generate_parameters(7, 512, backend)

    def test_dh_parameters_supported(self, backend):
        assert backend.dh_parameters_supported(23, 5)
        assert not backend.dh_parameters_supported(23, 18)

    def test_convert_to_numbers(self, backend):
        parameters = backend.generate_dh_private_key_and_parameters(2, 512)

        private = parameters.private_numbers()

        p = private.public_numbers.parameter_numbers.p
        g = private.public_numbers.parameter_numbers.g

        params = dh.DHParameterNumbers(p, g)
        public = dh.DHPublicNumbers(1, params)
        private = dh.DHPrivateNumbers(2, public)

        deserialized_params = params.parameters(backend)
        deserialized_public = public.public_key(backend)
        deserialized_private = private.private_key(backend)

        assert isinstance(deserialized_params,
                          dh.DHParametersWithSerialization)
        assert isinstance(deserialized_public,
                          dh.DHPublicKeyWithSerialization)
        assert isinstance(deserialized_private,
                          dh.DHPrivateKeyWithSerialization)

    def test_numbers_unsupported_parameters(self, backend):
        params = dh.DHParameterNumbers(23, 2)
        public = dh.DHPublicNumbers(1, params)
        private = dh.DHPrivateNumbers(2, public)

        with pytest.raises(ValueError):
            private.private_key(backend)

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

        assert isinstance(parameters, dh.DHParametersWithSerialization)
        parameter_numbers = parameters.parameter_numbers()
        assert isinstance(parameter_numbers, dh.DHParameterNumbers)
        assert bit_length(parameter_numbers.p) == key_size

        assert isinstance(public, dh.DHPublicKeyWithSerialization)
        assert isinstance(public.public_numbers(), dh.DHPublicNumbers)
        assert isinstance(public.parameters(), dh.DHParameters)

        assert isinstance(key, dh.DHPrivateKeyWithSerialization)
        assert isinstance(key.private_numbers(), dh.DHPrivateNumbers)
        assert isinstance(key.parameters(), dh.DHParameters)

    def test_exchange(self, backend):
        parameters = dh.generate_parameters(2, 512, backend)
        assert isinstance(parameters, dh.DHParameters)

        key1 = parameters.generate_private_key()
        key2 = parameters.generate_private_key()

        symkey1 = key1.exchange(key2.public_key())
        assert symkey1
        assert len(symkey1) == 512 // 8

        symkey2 = key2.exchange(key1.public_key())
        assert symkey1 == symkey2

    def test_exchange_algorithm(self, backend):
        parameters = dh.generate_parameters(2, 512, backend)

        key1 = parameters.generate_private_key()
        key2 = parameters.generate_private_key()

        shared_key_bytes = key2.exchange(key1.public_key())
        symkey = int_from_bytes(shared_key_bytes, 'big')

        symkey_manual = pow(key1.public_key().public_numbers().y,
                            key2.private_numbers().x,
                            parameters.parameter_numbers().p)

        assert symkey == symkey_manual

    def test_symmetric_key_padding(self, backend):
        """
        This test has specific parameters that produce a symmetric key
        In length 63 bytes instead 64. We make sure here that we add
        padding to the key.
        """
        p = int("11859949538425015739337467917303613431031019140213666"
                "129025407300654026585086345323066284800963463204246390"
                "256567934582260424238844463330887962689642467123")
        g = 2
        y = int("32155788395534640648739966373159697798396966919821525"
                "72238852825117261342483718574508213761865276905503199"
                "969908098203345481366464874759377454476688391248")
        x = int("409364065449673443397833358558926598469347813468816037"
                "268451847116982490733450463194921405069999008617231539"
                "7147035896687401350877308899732826446337707128")
        parameters = dh.DHParameterNumbers(p, g)
        public = dh.DHPublicNumbers(y, parameters)
        private = dh.DHPrivateNumbers(x, public)
        key = private.private_key(backend)
        symkey = key.exchange(public.public_key(backend))
        assert len(symkey) == 512 // 8
        assert symkey[:1] == b'\x00'

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("asymmetric", "DH", "bad_exchange.txt"),
            load_nist_vectors))
    def test_bad_exchange(self, backend, vector):
        parameters1 = dh.DHParameterNumbers(int(vector["p1"]),
                                            int(vector["g"]))
        public1 = dh.DHPublicNumbers(int(vector["y1"]), parameters1)
        private1 = dh.DHPrivateNumbers(int(vector["x1"]), public1)
        key1 = private1.private_key(backend)
        pub_key1 = key1.public_key()

        parameters2 = dh.DHParameterNumbers(int(vector["p2"]),
                                            int(vector["g"]))
        public2 = dh.DHPublicNumbers(int(vector["y2"]), parameters2)
        private2 = dh.DHPrivateNumbers(int(vector["x2"]), public2)
        key2 = private2.private_key(backend)
        pub_key2 = key2.public_key()

        if pub_key2.public_numbers().y >= parameters1.p:
            with pytest.raises(ValueError):
                key1.exchange(pub_key2)
        else:
            symkey1 = key1.exchange(pub_key2)
            assert symkey1

            symkey2 = key2.exchange(pub_key1)

            assert symkey1 != symkey2

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("asymmetric", "DH", "vec.txt"),
            load_nist_vectors))
    def test_dh_vectors(self, backend, vector):
        parameters = dh.DHParameterNumbers(int(vector["p"]),
                                           int(vector["g"]))
        public = dh.DHPublicNumbers(int(vector["y"]), parameters)
        private = dh.DHPrivateNumbers(int(vector["x"]), public)
        key = private.private_key(backend)
        symkey = key.exchange(public.public_key(backend))

        assert int_from_bytes(symkey, 'big') == int(vector["k"], 16)
