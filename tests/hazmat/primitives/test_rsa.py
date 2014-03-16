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

import binascii
import itertools
import os

import pytest

from cryptography import exceptions, utils
from cryptography.exceptions import UnsupportedInterface
from cryptography.hazmat.primitives import hashes, interfaces
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from ...utils import load_pkcs1_vectors, load_vectors_from_file


@utils.register_interface(interfaces.AsymmetricPadding)
class DummyPadding(object):
    name = "UNSUPPORTED-PADDING"


def _modinv(e, m):
    """
    Modular Multiplicative Inverse.  Returns x such that: (x*e) mod m == 1
    """
    x1, y1, x2, y2 = 1, 0, 0, 1
    a, b = e, m
    while b > 0:
        q, r = divmod(a, b)
        xn, yn = x1 - q * x2, y1 - q * y2
        a, b, x1, y1, x2, y2 = b, r, x2, y2, xn, yn
    return x1 % m


def _check_rsa_private_key(skey):
    assert skey
    assert skey.modulus
    assert skey.public_exponent
    assert skey.private_exponent
    assert skey.p * skey.q == skey.modulus
    assert skey.key_size
    assert skey.dmp1 == skey.d % (skey.p - 1)
    assert skey.dmq1 == skey.d % (skey.q - 1)
    assert skey.iqmp == _modinv(skey.q, skey.p)

    pkey = skey.public_key()
    assert pkey
    assert skey.modulus == pkey.modulus
    assert skey.public_exponent == pkey.public_exponent
    assert skey.key_size == pkey.key_size


def _flatten_pkcs1_examples(vectors):
    flattened_vectors = []
    for vector in vectors:
        examples = vector[0].pop("examples")
        for example in examples:
            merged_vector = (vector[0], vector[1], example)
            flattened_vectors.append(merged_vector)

    return flattened_vectors


def test_modular_inverse():
    p = int(
        "d1f9f6c09fd3d38987f7970247b85a6da84907753d42ec52bc23b745093f4fff5cff3"
        "617ce43d00121a9accc0051f519c76e08cf02fc18acfe4c9e6aea18da470a2b611d2e"
        "56a7b35caa2c0239bc041a53cc5875ca0b668ae6377d4b23e932d8c995fd1e58ecfd8"
        "c4b73259c0d8a54d691cca3f6fb85c8a5c1baf588e898d481", 16
    )
    q = int(
        "d1519255eb8f678c86cfd06802d1fbef8b664441ac46b73d33d13a8404580a33a8e74"
        "cb2ea2e2963125b3d454d7a922cef24dd13e55f989cbabf64255a736671f4629a47b5"
        "b2347cfcd669133088d1c159518531025297c2d67c9da856a12e80222cd03b4c6ec0f"
        "86c957cb7bb8de7a127b645ec9e820aa94581e4762e209f01", 16
    )
    assert _modinv(q, p) == int(
        "0275e06afa722999315f8f322275483e15e2fb46d827b17800f99110b269a6732748f"
        "624a382fa2ed1ec68c99f7fc56fb60e76eea51614881f497ba7034c17dde955f92f15"
        "772f8b2b41f3e56d88b1e096cdd293eba4eae1e82db815e0fadea0c4ec971bc6fd875"
        "c20e67e48c31a611e98d32c6213ae4c4d7b53023b2f80c538", 16
    )


@pytest.mark.rsa
class TestRSA(object):
    @pytest.mark.parametrize(
        "public_exponent,key_size",
        itertools.product(
            (3, 5, 65537),
            (1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1536, 2048)
        )
    )
    def test_generate_rsa_keys(self, backend, public_exponent, key_size):
        skey = rsa.RSAPrivateKey.generate(public_exponent, key_size, backend)
        _check_rsa_private_key(skey)
        assert skey.key_size == key_size
        assert skey.public_exponent == public_exponent

    def test_generate_bad_rsa_key(self, backend):
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey.generate(public_exponent=1,
                                       key_size=2048,
                                       backend=backend)

        with pytest.raises(ValueError):
            rsa.RSAPrivateKey.generate(public_exponent=4,
                                       key_size=2048,
                                       backend=backend)

    def test_cant_generate_insecure_tiny_key(self, backend):
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey.generate(public_exponent=65537,
                                       key_size=511,
                                       backend=backend)

        with pytest.raises(ValueError):
            rsa.RSAPrivateKey.generate(public_exponent=65537,
                                       key_size=256,
                                       backend=backend)

    @pytest.mark.parametrize(
        "pkcs1_example",
        load_vectors_from_file(
            os.path.join(
                "asymmetric", "RSA", "pkcs-1v2-1d2-vec", "pss-vect.txt"),
            load_pkcs1_vectors
        )
    )
    def test_load_pss_vect_example_keys(self, pkcs1_example):
        secret, public = pkcs1_example

        skey = rsa.RSAPrivateKey(
            p=secret["p"],
            q=secret["q"],
            private_exponent=secret["private_exponent"],
            dmp1=secret["dmp1"],
            dmq1=secret["dmq1"],
            iqmp=secret["iqmp"],
            public_exponent=secret["public_exponent"],
            modulus=secret["modulus"]
        )
        assert skey
        _check_rsa_private_key(skey)

        pkey = rsa.RSAPublicKey(
            public_exponent=public["public_exponent"],
            modulus=public["modulus"]
        )
        assert pkey

        pkey2 = skey.public_key()
        assert pkey2

        assert skey.modulus == pkey.modulus
        assert skey.modulus == skey.n
        assert skey.public_exponent == pkey.public_exponent
        assert skey.public_exponent == skey.e
        assert skey.private_exponent == skey.d

        assert pkey.modulus
        assert pkey.modulus == pkey2.modulus
        assert pkey.modulus == pkey.n
        assert pkey.public_exponent == pkey2.public_exponent
        assert pkey.public_exponent == pkey.e

        assert skey.key_size
        assert skey.key_size == pkey.key_size
        assert skey.key_size == pkey2.key_size

    def test_invalid_private_key_argument_types(self):
        with pytest.raises(TypeError):
            rsa.RSAPrivateKey(None, None, None, None, None, None, None, None)

    def test_invalid_public_key_argument_types(self):
        with pytest.raises(TypeError):
            rsa.RSAPublicKey(None, None)

    def test_invalid_private_key_argument_values(self):
        # Start with p=3, q=11, private_exponent=3, public_exponent=7,
        # modulus=33, dmp1=1, dmq1=3, iqmp=2. Then change one value at
        # a time to test the bounds.

        # Test a modulus < 3.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=2
            )

        # Test a modulus != p * q.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=35
            )

        # Test a p > modulus.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=37,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

        # Test a q > modulus.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=37,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

        # Test a dmp1 > modulus.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=35,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

        # Test a dmq1 > modulus.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=35,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

        # Test an iqmp > modulus.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=35,
                public_exponent=7,
                modulus=33
            )

        # Test a private_exponent > modulus
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=37,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

        # Test a public_exponent < 3
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=1,
                modulus=33
            )

        # Test a public_exponent > modulus
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=65537,
                modulus=33
            )

        # Test a public_exponent that is not odd.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=6,
                modulus=33
            )

        # Test a dmp1 that is not odd.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=2,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

        # Test a dmq1 that is not odd.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=4,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

    def test_invalid_public_key_argument_values(self):
        # Start with public_exponent=7, modulus=15. Then change one value at a
        # time to test the bounds.

        # Test a modulus < 3.
        with pytest.raises(ValueError):
            rsa.RSAPublicKey(public_exponent=7, modulus=2)

        # Test a public_exponent < 3
        with pytest.raises(ValueError):
            rsa.RSAPublicKey(public_exponent=1, modulus=15)

        # Test a public_exponent > modulus
        with pytest.raises(ValueError):
            rsa.RSAPublicKey(public_exponent=17, modulus=15)

        # Test a public_exponent that is not odd.
        with pytest.raises(ValueError):
            rsa.RSAPublicKey(public_exponent=6, modulus=15)


def test_rsa_generate_invalid_backend():
    pretend_backend = object()

    with pytest.raises(UnsupportedInterface):
        rsa.RSAPrivateKey.generate(65537, 2048, pretend_backend)


@pytest.mark.rsa
class TestRSASignature(object):
    @pytest.mark.parametrize(
        "pkcs1_example",
        _flatten_pkcs1_examples(load_vectors_from_file(
            os.path.join(
                "asymmetric", "RSA", "pkcs1v15sign-vectors.txt"),
            load_pkcs1_vectors
        ))
    )
    def test_pkcs1v15_signing(self, pkcs1_example, backend):
        private, public, example = pkcs1_example
        private_key = rsa.RSAPrivateKey(
            p=private["p"],
            q=private["q"],
            private_exponent=private["private_exponent"],
            dmp1=private["dmp1"],
            dmq1=private["dmq1"],
            iqmp=private["iqmp"],
            public_exponent=private["public_exponent"],
            modulus=private["modulus"]
        )
        signer = private_key.signer(padding.PKCS1v15(), hashes.SHA1(), backend)
        signer.update(binascii.unhexlify(example["message"]))
        signature = signer.finalize()
        assert binascii.hexlify(signature) == example["signature"]

    def test_use_after_finalize(self, backend):
        private_key = rsa.RSAPrivateKey.generate(
            public_exponent=65537,
            key_size=512,
            backend=backend
        )
        signer = private_key.signer(padding.PKCS1v15(), hashes.SHA1(), backend)
        signer.update(b"sign me")
        signer.finalize()
        with pytest.raises(exceptions.AlreadyFinalized):
            signer.finalize()
        with pytest.raises(exceptions.AlreadyFinalized):
            signer.update(b"more data")

    def test_unsupported_padding(self, backend):
        private_key = rsa.RSAPrivateKey.generate(
            public_exponent=65537,
            key_size=512,
            backend=backend
        )
        with pytest.raises(exceptions.UnsupportedPadding):
            private_key.signer(DummyPadding(), hashes.SHA1(), backend)

    def test_padding_incorrect_type(self, backend):
        private_key = rsa.RSAPrivateKey.generate(
            public_exponent=65537,
            key_size=512,
            backend=backend
        )
        with pytest.raises(TypeError):
            private_key.signer("notpadding", hashes.SHA1(), backend)

    def test_rsa_signer_invalid_backend(self, backend):
        pretend_backend = object()
        private_key = rsa.RSAPrivateKey.generate(65537, 2048, backend)

        with pytest.raises(UnsupportedInterface):
            private_key.signer(
                padding.PKCS1v15(), hashes.SHA256, pretend_backend)


@pytest.mark.rsa
class TestRSAVerification(object):
    @pytest.mark.parametrize(
        "pkcs1_example",
        _flatten_pkcs1_examples(load_vectors_from_file(
            os.path.join(
                "asymmetric", "RSA", "pkcs1v15sign-vectors.txt"),
            load_pkcs1_vectors
        ))
    )
    def test_pkcs1v15_verification(self, pkcs1_example, backend):
        private, public, example = pkcs1_example
        public_key = rsa.RSAPublicKey(
            public_exponent=public["public_exponent"],
            modulus=public["modulus"]
        )
        verifier = public_key.verifier(
            binascii.unhexlify(example["signature"]),
            padding.PKCS1v15(),
            hashes.SHA1(),
            backend
        )
        verifier.update(binascii.unhexlify(example["message"]))
        verifier.verify()

    def test_invalid_pkcs1v15_signature_wrong_data(self, backend):
        private_key = rsa.RSAPrivateKey.generate(
            public_exponent=65537,
            key_size=512,
            backend=backend
        )
        public_key = private_key.public_key()
        signer = private_key.signer(padding.PKCS1v15(), hashes.SHA1(), backend)
        signer.update(b"sign me")
        signature = signer.finalize()
        verifier = public_key.verifier(
            signature,
            padding.PKCS1v15(),
            hashes.SHA1(),
            backend
        )
        verifier.update(b"incorrect data")
        with pytest.raises(exceptions.InvalidSignature):
            verifier.verify()

    def test_invalid_pkcs1v15_signature_wrong_key(self, backend):
        private_key = rsa.RSAPrivateKey.generate(
            public_exponent=65537,
            key_size=512,
            backend=backend
        )
        private_key2 = rsa.RSAPrivateKey.generate(
            public_exponent=65537,
            key_size=512,
            backend=backend
        )
        public_key = private_key2.public_key()
        signer = private_key.signer(padding.PKCS1v15(), hashes.SHA1(), backend)
        signer.update(b"sign me")
        signature = signer.finalize()
        verifier = public_key.verifier(
            signature,
            padding.PKCS1v15(),
            hashes.SHA1(),
            backend
        )
        verifier.update(b"sign me")
        with pytest.raises(exceptions.InvalidSignature):
            verifier.verify()

    def test_use_after_finalize(self, backend):
        private_key = rsa.RSAPrivateKey.generate(
            public_exponent=65537,
            key_size=512,
            backend=backend
        )
        public_key = private_key.public_key()
        signer = private_key.signer(padding.PKCS1v15(), hashes.SHA1(), backend)
        signer.update(b"sign me")
        signature = signer.finalize()

        verifier = public_key.verifier(
            signature,
            padding.PKCS1v15(),
            hashes.SHA1(),
            backend
        )
        verifier.update(b"sign me")
        verifier.verify()
        with pytest.raises(exceptions.AlreadyFinalized):
            verifier.verify()
        with pytest.raises(exceptions.AlreadyFinalized):
            verifier.update(b"more data")

    def test_unsupported_padding(self, backend):
        private_key = rsa.RSAPrivateKey.generate(
            public_exponent=65537,
            key_size=512,
            backend=backend
        )
        public_key = private_key.public_key()
        with pytest.raises(exceptions.UnsupportedPadding):
            public_key.verifier(b"sig", DummyPadding(), hashes.SHA1(), backend)

    def test_padding_incorrect_type(self, backend):
        private_key = rsa.RSAPrivateKey.generate(
            public_exponent=65537,
            key_size=512,
            backend=backend
        )
        public_key = private_key.public_key()
        with pytest.raises(TypeError):
            public_key.verifier(b"sig", "notpadding", hashes.SHA1(), backend)

    def test_rsa_verifier_invalid_backend(self, backend):
        pretend_backend = object()
        private_key = rsa.RSAPrivateKey.generate(65537, 2048, backend)
        public_key = private_key.public_key()

        with pytest.raises(UnsupportedInterface):
            public_key.verifier(
                b"foo", padding.PKCS1v15(), hashes.SHA256(), pretend_backend)


class TestMGF1(object):
    def test_invalid_hash_algorithm(self):
        with pytest.raises(TypeError):
            padding.MGF1(b"not_a_hash", 0)

    def test_invalid_salt_length_not_integer(self):
        with pytest.raises(TypeError):
            padding.MGF1(hashes.SHA1(), b"not_a_length")

    def test_invalid_salt_length_negative_integer(self):
        with pytest.raises(ValueError):
            padding.MGF1(hashes.SHA1(), -1)

    def test_valid_mgf1_parameters(self):
        algorithm = hashes.SHA1()
        salt_length = algorithm.digest_size
        mgf = padding.MGF1(algorithm, salt_length)
        assert mgf._algorithm == algorithm
        assert mgf._salt_length == salt_length

    def test_valid_mgf1_parameters_maximum(self):
        algorithm = hashes.SHA1()
        mgf = padding.MGF1(algorithm, padding.MGF1.MAX_LENGTH)
        assert mgf._algorithm == algorithm
        assert mgf._salt_length == padding.MGF1.MAX_LENGTH
