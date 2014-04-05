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

from cryptography.exceptions import _Reasons
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.utils import bit_length

from ...utils import (
    load_vectors_from_file, load_fips_dsa_key_pair_vectors,
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
    _parameters_1024 = {
        'p': 'd38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b725ef341eabb47'
        'cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae7912102b6b502e59050b5b21ce26'
        '3dddb2044b652236f4d42ab4b5d6aa73189cef1ace778d7845a5c1c1c7147123188f8'
        'dc551054ee162b634d60f097f719076640e20980a0093113a8bd73',

        'q': '96c5390a8b612c0e422bb2b0ea194a3ec935a281',

        'g': '06b7861abbd35cc89e79c52f68d20875389b127361ca66822138ce4991d2b862'
        '259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3d300042bdf15762812b633'
        '3ef7b07ceba78607610fcc9ee68491dbc1e34cd12615474e52b18bc934fb00c61d39e'
        '7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc076341a7e7d9',

        'x': '8185fee9cc7c0e91fd85503274f1cd5a3fd15a49',

        'y': '6f26d98d41de7d871b6381851c9d91fa03942092ab6097e76422070edb71db44'
        'ff568280fdb1709f8fc3feab39f1f824adaeb2a298088156ac31af1aa04bf54f475bd'
        'cfdcf2f8a2dd973e922d83e76f016558617603129b21c70bf7d0e5dc9e68fe332e295'
        'b65876eb9a12fe6fca9f1a1ce80204646bf99b5771d249a6fea627'
    }

    _parameters_2048 = {
        'p': 'ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace5e9c41434c9c'
        'f0a8e9498acb0f4663c08b4484eace845f6fb17dac62c98e706af0fc74e4da1c6c2b3'
        'fbf5a1d58ff82fc1a66f3e8b12252c40278fff9dd7f102eed2cb5b7323ebf1908c234'
        'd935414dded7f8d244e54561b0dca39b301de8c49da9fb23df33c6182e3f983208c56'
        '0fb5119fbf78ebe3e6564ee235c6a15cbb9ac247baba5a423bc6582a1a9d8a2b4f0e9'
        'e3d9dbac122f750dd754325135257488b1f6ecabf21bff2947fe0d3b2cb7ffe67f4e7'
        'fcdf1214f6053e72a5bb0dd20a0e9fe6db2df0a908c36e95e60bf49ca4368b8b892b9'
        'c79f61ef91c47567c40e1f80ac5aa66ef7',

        'q': '8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b18f'
        '507192c19d',

        'g': 'e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6ccb6b1913413d'
        '344d1d8d84a333839d88eee431521f6e357c16e6a93be111a98076739cd401bab3b9d'
        '565bf4fb99e9d185b1e14d61c93700133f908bae03e28764d107dcd2ea76742176220'
        '74bb19efff482f5f5c1a86d5551b2fc68d1c6e9d8011958ef4b9c2a3a55d0d3c882e6'
        'ad7f9f0f3c61568f78d0706b10a26f23b4f197c322b825002284a0aca91807bba98ec'
        'e912b80e10cdf180cf99a35f210c1655fbfdd74f13b1b5046591f8403873d12239834'
        'dd6c4eceb42bf7482e1794a1601357b629ddfa971f2ed273b146ec1ca06d0adf55dd9'
        '1d65c37297bda78c6d210c0bc26e558302',

        'x': '405772da6e90d809e77d5de796562a2dd4dfd10ef00a83a3aba6bd'
        '818a0348a1',

        'y': '6b32e31ab9031dc4dd0b5039a78d07826687ab087ae6de4736f5b0434e125309'
        '2e8a0b231f9c87f3fc8a4cb5634eb194bf1b638b7a7889620ce6711567e36aa36cda4'
        '604cfaa601a45918371d4ccf68d8b10a50a0460eb1dc0fff62ef5e6ee4d473e18ea4a'
        '66c196fb7e677a49b48241a0b4a97128eff30fa437050501a584f8771e7280d26d5af'
        '30784039159c11ebfea10b692fd0a58215eeb18bff117e13f08db792ed4151a218e4b'
        'ed8dddfb0793225bd1e9773505166f4bd8cedbb286ea28232972da7bae836ba97329b'
        'a6b0a36508e50a52a7675e476d4d4137eae13f22a9d2fefde708ba8f34bf336c6e763'
        '31761e4b0617633fe7ec3f23672fb19d27'
    }

    _parameters_3072 = {
        'p': 'f335666dd1339165af8b9a5e3835adfe15c158e4c3c7bd53132e7d5828c352f5'
        '93a9a787760ce34b789879941f2f01f02319f6ae0b756f1a842ba54c85612ed632ee2'
        'd79ef17f06b77c641b7b080aff52a03fc2462e80abc64d223723c236deeb7d201078e'
        'c01ca1fbc1763139e25099a84ec389159c409792080736bd7caa816b92edf23f2c351'
        'f90074aa5ea2651b372f8b58a0a65554db2561d706a63685000ac576b7e4562e262a1'
        '4285a9c6370b290e4eb7757527d80b6c0fd5df831d36f3d1d35f12ab060548de1605f'
        'd15f7c7aafed688b146a02c945156e284f5b71282045aba9844d48b5df2e9e7a58871'
        '21eae7d7b01db7cdf6ff917cd8eb50c6bf1d54f90cce1a491a9c74fea88f7e7230b04'
        '7d16b5a6027881d6f154818f06e513faf40c8814630e4e254f17a47bfe9cb519b9828'
        '9935bf17673ae4c8033504a20a898d0032ee402b72d5986322f3bdfb27400561f7476'
        'cd715eaabb7338b854e51fc2fa026a5a579b6dcea1b1c0559c13d3c1136f303f4b4d2'
        '5ad5b692229957',

        'q': 'd3eba6521240694015ef94412e08bf3cf8d635a455a398d6f210f'
        '6169041653b',

        'g': 'ce84b30ddf290a9f787a7c2f1ce92c1cbf4ef400e3cd7ce4978db2104d7394b4'
        '93c18332c64cec906a71c3778bd93341165dee8e6cd4ca6f13afff531191194ada55e'
        'cf01ff94d6cf7c4768b82dd29cd131aaf202aefd40e564375285c01f3220af4d70b96'
        'f1395420d778228f1461f5d0b8e47357e87b1fe3286223b553e3fc9928f16ae3067de'
        'd6721bedf1d1a01bfd22b9ae85fce77820d88cdf50a6bde20668ad77a707d1c60fcc5'
        'd51c9de488610d0285eb8ff721ff141f93a9fb23c1d1f7654c07c46e58836d1652828'
        'f71057b8aff0b0778ef2ca934ea9d0f37daddade2d823a4d8e362721082e279d003b5'
        '75ee59fd050d105dfd71cd63154efe431a0869178d9811f4f231dc5dcf3b0ec0f2b0f'
        '9896c32ec6c7ee7d60aa97109e09224907328d4e6acd10117e45774406c4c947da802'
        '0649c3168f690e0bd6e91ac67074d1d436b58ae374523deaf6c93c1e6920db4a080b7'
        '44804bb073cecfe83fa9398cf150afa286dc7eb7949750cf5001ce104e9187f7e1685'
        '9afa8fd0d775ae',

        'x': 'b2764c46113983777d3e7e97589f1303806d14ad9f2f1ef033097'
        'de954b17706',

        'y': '814824e435e1e6f38daa239aad6dad21033afce6a3ebd35c1359348a0f241887'
        '1968c2babfc2baf47742148828f8612183178f126504da73566b6bab33ba1f124c15a'
        'a461555c2451d86c94ee21c3e3fc24c55527e01b1f03adcdd8ec5cb08082803a7b6a8'
        '29c3e99eeb332a2cf5c035b0ce0078d3d414d31fa47e9726be2989b8d06da2e6cd363'
        'f5a7d1515e3f4925e0b32adeae3025cc5a996f6fd27494ea408763de48f3bb39f6a06'
        '514b019899b312ec570851637b8865cff3a52bf5d54ad5a19e6e400a2d33251055d0a'
        '440b50d53f4791391dc754ad02b9eab74c46b4903f9d76f824339914db108057af7cd'
        'e657d41766a99991ac8787694f4185d6f91d7627048f827b405ec67bf2fe56141c4c5'
        '81d8c317333624e073e5879a82437cb0c7b435c0ce434e15965db1315d64895991e6b'
        'be7dac040c42052408bbc53423fd31098248a58f8a67da3a39895cd0cc927515d044c'
        '1e3cb6a3259c3d0da354cce89ea3552c59609db10ee989986527436af21d9485ddf25'
        'f90f7dff6d2bae'
    }

    def test_generate_dsa_parameters(self, backend):
        parameters = dsa.DSAParameters.generate(1024, backend)
        assert bit_length(parameters.p) == 1024

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
        parameters = dsa.DSAParameters(modulus=vector['p'],
                                       subgroup_order=vector['q'],
                                       generator=vector['g'])
        skey = dsa.DSAPrivateKey.generate(parameters, backend)

        skey_parameters = skey.parameters()
        assert skey_parameters.p == vector['p']
        assert skey_parameters.q == vector['q']
        assert skey_parameters.g == vector['g']
        assert skey.key_size == bit_length(vector['p'])
        assert skey.y == pow(skey_parameters.g, skey.x, skey_parameters.p)

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
            modulus=int(self._parameters_1024['p'], 16),
            subgroup_order=int(self._parameters_1024['q'], 16),
            generator=int(self._parameters_1024['g'], 16))

        assert parameters
        assert parameters.modulus
        assert parameters.subgroup_order
        assert parameters.generator
        assert parameters.modulus == parameters.p
        assert parameters.subgroup_order == parameters.q
        assert parameters.generator == parameters.g

        pub_key = dsa.DSAPublicKey(
            modulus=int(self._parameters_1024["p"], 16),
            subgroup_order=int(self._parameters_1024["q"], 16),
            generator=int(self._parameters_1024["g"], 16),
            y=int(self._parameters_1024["y"], 16)
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
            modulus=int(self._parameters_1024["p"], 16),
            subgroup_order=int(self._parameters_1024["q"], 16),
            generator=int(self._parameters_1024["g"], 16),
            x=int(self._parameters_1024["x"], 16),
            y=int(self._parameters_1024["y"], 16)
        )
        assert skey
        _check_dsa_private_key(skey)
        skey_parameters = skey.parameters()
        assert skey_parameters
        assert skey_parameters.modulus
        assert skey_parameters.subgroup_order
        assert skey_parameters.generator

        pkey = dsa.DSAPublicKey(
            modulus=int(self._parameters_1024["p"], 16),
            subgroup_order=int(self._parameters_1024["q"], 16),
            generator=int(self._parameters_1024["g"], 16),
            y=int(self._parameters_1024["y"], 16)
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
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_1024['g'], 16)
            )

        # Test a modulus < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 2000,
                subgroup_order=int(self._parameters_2048['q'], 16),
                generator=int(self._parameters_2048['g'], 16)
            )

        # Test a modulus < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 3000,
                subgroup_order=int(self._parameters_3072['q'], 16),
                generator=int(self._parameters_3072['g'], 16)
            )

        # Test a modulus > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 3100,
                subgroup_order=int(self._parameters_3072['q'], 16),
                generator=int(self._parameters_3072['g'], 16)
            )

        # Test a subgroup_order < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=2 ** 150,
                generator=int(self._parameters_1024['g'], 16)
            )

        # Test a subgroup_order < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._parameters_2048['p'], 16),
                subgroup_order=2 ** 250,
                generator=int(self._parameters_2048['g'], 16)
            )

        # Test a subgroup_order > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._parameters_3072['p'], 16),
                subgroup_order=2 ** 260,
                generator=int(self._parameters_3072['g'], 16)
            )

        # Test a modulus, subgroup_order pair of (1024, 256) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_2048['q'], 16),
                generator=int(self._parameters_1024['g'], 16)
            )

        # Test a modulus, subgroup_order pair of (2048, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._parameters_2048['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_2048['g'], 16)
            )

        # Test a modulus, subgroup_order pair of (3072, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._parameters_3072['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_3072['g'], 16)
            )

        # Test a generator < 1
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=0
            )

        # Test a generator = 1
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=1
            )

        # Test a generator > modulus
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=2 ** 1200
            )

    def test_invalid_dsa_private_key_arguments(self):
        # Test a modulus < 1024 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 1000,
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_1024['g'], 16),
                x=int(self._parameters_1024['x'], 16),
                y=int(self._parameters_1024['y'], 16)
            )

        # Test a modulus < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 2000,
                subgroup_order=int(self._parameters_2048['q'], 16),
                generator=int(self._parameters_2048['g'], 16),
                x=int(self._parameters_2048['x'], 16),
                y=int(self._parameters_2048['y'], 16)
            )

        # Test a modulus < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 3000,
                subgroup_order=int(self._parameters_3072['q'], 16),
                generator=int(self._parameters_3072['g'], 16),
                x=int(self._parameters_3072['x'], 16),
                y=int(self._parameters_3072['y'], 16)
            )

        # Test a modulus > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 3100,
                subgroup_order=int(self._parameters_3072['q'], 16),
                generator=int(self._parameters_3072['g'], 16),
                x=int(self._parameters_3072['x'], 16),
                y=int(self._parameters_3072['y'], 16)
            )

        # Test a subgroup_order < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=2 ** 150,
                generator=int(self._parameters_1024['g'], 16),
                x=int(self._parameters_1024['x'], 16),
                y=int(self._parameters_1024['y'], 16)
            )

        # Test a subgroup_order < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_2048['p'], 16),
                subgroup_order=2 ** 250,
                generator=int(self._parameters_2048['g'], 16),
                x=int(self._parameters_2048['x'], 16),
                y=int(self._parameters_2048['y'], 16)
            )

        # Test a subgroup_order > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_3072['p'], 16),
                subgroup_order=2 ** 260,
                generator=int(self._parameters_3072['g'], 16),
                x=int(self._parameters_3072['x'], 16),
                y=int(self._parameters_3072['y'], 16)
            )

        # Test a modulus, subgroup_order pair of (1024, 256) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_2048['q'], 16),
                generator=int(self._parameters_1024['g'], 16),
                x=int(self._parameters_1024['x'], 16),
                y=int(self._parameters_1024['y'], 16)
            )

        # Test a modulus, subgroup_order pair of (2048, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_2048['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_2048['g'], 16),
                x=int(self._parameters_2048['x'], 16),
                y=int(self._parameters_2048['y'], 16)
            )

        # Test a modulus, subgroup_order pair of (3072, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_3072['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_3072['g'], 16),
                x=int(self._parameters_3072['x'], 16),
                y=int(self._parameters_3072['y'], 16)
            )

        # Test a generator < 1
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=0,
                x=int(self._parameters_1024['x'], 16),
                y=int(self._parameters_1024['y'], 16)
            )

        # Test a generator = 1
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=1,
                x=int(self._parameters_1024['x'], 16),
                y=int(self._parameters_1024['y'], 16)
            )

        # Test a generator > modulus
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=2 ** 1200,
                x=int(self._parameters_1024['x'], 16),
                y=int(self._parameters_1024['y'], 16)
            )

        # Test x = 0
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_1024['g'], 16),
                x=0,
                y=int(self._parameters_1024['y'], 16)
            )

        # Test x < 0
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_1024['g'], 16),
                x=-2,
                y=int(self._parameters_1024['y'], 16)
            )

        # Test x = subgroup_order
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_1024['g'], 16),
                x=2 ** 159,
                y=int(self._parameters_1024['y'], 16)
            )

        # Test x > subgroup_order
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_1024['g'], 16),
                x=2 ** 200,
                y=int(self._parameters_1024['y'], 16)
            )

        # Test y != (generator ** x) % modulus
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_1024['g'], 16),
                x=int(self._parameters_1024['x'], 16),
                y=2 ** 100
            )

        # Test a non-integer y value
        with pytest.raises(TypeError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_1024['g'], 16),
                x=int(self._parameters_1024['x'], 16),
                y=None
            )

        # Test a non-integer x value
        with pytest.raises(TypeError):
            dsa.DSAPrivateKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_1024['g'], 16),
                x=None,
                y=int(self._parameters_1024['x'], 16)
            )

    def test_invalid_dsa_public_key_arguments(self):
        # Test a modulus < 1024 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=2 ** 1000,
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_1024['g'], 16),
                y=int(self._parameters_1024['y'], 16)
            )

        # Test a modulus < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=2 ** 2000,
                subgroup_order=int(self._parameters_2048['q'], 16),
                generator=int(self._parameters_2048['g'], 16),
                y=int(self._parameters_2048['y'], 16)
            )

        # Test a modulus < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=2 ** 3000,
                subgroup_order=int(self._parameters_3072['q'], 16),
                generator=int(self._parameters_3072['g'], 16),
                y=int(self._parameters_3072['y'], 16)
            )

        # Test a modulus > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=2 ** 3100,
                subgroup_order=int(self._parameters_3072['q'], 16),
                generator=int(self._parameters_3072['g'], 16),
                y=int(self._parameters_3072['y'], 16)
            )

        # Test a subgroup_order < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=2 ** 150,
                generator=int(self._parameters_1024['g'], 16),
                y=int(self._parameters_1024['y'], 16)
            )

        # Test a subgroup_order < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=int(self._parameters_2048['p'], 16),
                subgroup_order=2 ** 250,
                generator=int(self._parameters_2048['g'], 16),
                y=int(self._parameters_2048['y'], 16)
            )

        # Test a subgroup_order > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=int(self._parameters_3072['p'], 16),
                subgroup_order=2 ** 260,
                generator=int(self._parameters_3072['g'], 16),
                y=int(self._parameters_3072['y'], 16)
            )

        # Test a modulus, subgroup_order pair of (1024, 256) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_2048['q'], 16),
                generator=int(self._parameters_1024['g'], 16),
                y=int(self._parameters_1024['y'], 16)
            )

        # Test a modulus, subgroup_order pair of (2048, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=int(self._parameters_2048['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_2048['g'], 16),
                y=int(self._parameters_2048['y'], 16)
            )

        # Test a modulus, subgroup_order pair of (3072, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=int(self._parameters_3072['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_3072['g'], 16),
                y=int(self._parameters_3072['y'], 16)
            )

        # Test a generator < 1
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=0,
                y=int(self._parameters_1024['y'], 16)
            )

        # Test a generator = 1
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=1,
                y=int(self._parameters_1024['y'], 16)
            )

        # Test a generator > modulus
        with pytest.raises(ValueError):
            dsa.DSAPublicKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=2 ** 1200,
                y=int(self._parameters_1024['y'], 16)
            )

        # Test a non-integer y value
        with pytest.raises(TypeError):
            dsa.DSAPublicKey(
                modulus=int(self._parameters_1024['p'], 16),
                subgroup_order=int(self._parameters_1024['q'], 16),
                generator=int(self._parameters_1024['g'], 16),
                y=None
            )


def test_dsa_generate_invalid_backend():
    pretend_backend = object()

    with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
        dsa.DSAParameters.generate(1024, pretend_backend)

    pretend_parameters = object()
    with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
        dsa.DSAPrivateKey.generate(pretend_parameters, pretend_backend)
