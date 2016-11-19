# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.hazmat.backends.interfaces import DHBackend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.utils import bit_length, int_from_bytes


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

    def test_serialize_unsupported_parameters(self, backend):
        params = dh.DHParameterNumbers(23, 18)
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

    bad_tls_exchange_params = [(
        {"p": int("6982449264326893170076800712455263"
                  "2914693498290905162222102226685181"
                  "0259029512897595134586351317114030"
                  "1173103075603894877550567268976511"
                  "279764959149528443"),
         "g": 2,
         "x": int("4801532380147672323646734353223620"
                  "0223913925165663903153279130290356"
                  "41903575640872665137366552076226566"
                  "4110044762552045668678795518280942"
                  "89388660251782046"),
         "y": int("8216041600942816864205479007817860"
                  "7361901087268262789169849789253403"
                  "2059614878030140061466421083272893"
                  "5265095314650297739643980635231692"
                  "43002396742005311")},
        {"p": int("1108095621796176823235350761660827"
                  "1011094948914260968400815080208586"
                  "3439139018738944767844200988947233"
                  "3299069268667473167480147686113895"
                  "4727825965908678667"),
         "g": 2,
         "y": int("1025098211254238591801738100952047"
                  "3894895926030138509814084625750094"
                  "2049666491992707660836809099228649"
                  "7242598386848872721869846444110626"
                  "9212018923589462134"),
         "x": int("5711420683916244371478141649351505"
                  "9293653471293991366753725660818826"
                  "1163006378301681679579405550775134"
                  "5814825076698378102524000583805069"
                  "503046990368030659")}),
        (
        {"p": int("1290001387274624996453358829942421"
                  "7034480441280987975922107615584280"
                  "9738034589599361811799673714083357"
                  "3278333490322408794830356113283327"
                  "0378314994720245923"),
         "g": 2,
         "x": int("6071003937964305313717247598692016"
                  "4373340134492385874028454100455857"
                  "8508247149222055619947395539853273"
                  "4458121110746407155944589178844230"
                  "676809305984951446"),
         "y": int("7991113599078333875847794507844575"
                  "6175050224504463981970753203231868"
                  "0136551315101498332139075360575330"
                  "6200081479128423955529753566986512"
                  "451925943417370573")},
        {"p": int("8230910504630293046781610423436023"
                  "7855700588139834267641276801633860"
                  "7909748155624229540803040656254044"
                  "1574901920011043362099679138268556"
                  "410914150106172603"),
         "g": 2,
         "y": int("3153667608586790035405826466812972"
                  "2719824210153531748906003251088123"
                  "2786742480574293420585405275184080"
                  "7361048259220540363086632109209018"
                  "127565889223022306"),
         "x": int("5094233318592725701435923671489794"
                  "1349417222942424283646053422521046"
                  "7803823560524571564089891180147290"
                  "6659807096135548788171923289152060"
                  "442445002898139883")})
    ]

    @pytest.mark.parametrize("params_pair", bad_tls_exchange_params)
    def test_bad_tls_exchange(self, backend, params_pair):
        parameters1 = dh.DHParameterNumbers(params_pair[0]["p"],
                                            params_pair[0]["g"])
        public1 = dh.DHPublicNumbers(params_pair[0]["y"], parameters1)
        private1 = dh.DHPrivateNumbers(params_pair[0]["x"], public1)
        key1 = private1.private_key(backend)
        pub_key1 = key1.public_key()

        parameters2 = dh.DHParameterNumbers(params_pair[1]["p"],
                                            params_pair[1]["g"])
        public2 = dh.DHPublicNumbers(params_pair[1]["y"], parameters2)
        private2 = dh.DHPrivateNumbers(params_pair[1]["x"], public2)
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
