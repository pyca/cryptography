# -*- encoding: utf8 -*-

import array
import threading
import hashlib as python_hashlib
import hmac

import pytest
import six

from cryptography import utils
from cryptography.hazmat.primitives import interfaces, hashes
from cryptography.py.hashlib import Hashlib, _new_hashlib_adapter, _buffer


@pytest.fixture()
def hashlib(backend):
    return Hashlib(backend)


@utils.register_interface(interfaces.HashAlgorithm)
class UnsupportedDummyHash(object):
    name = "unsupported-dummy-hash"


class TestHashlib(object):
    """
    Hashlib tests, mostly based on the tests PyPy ported from CPython, plus
    some extras.
    """

    supported_hash_names = ('md5', 'MD5', 'sha1', 'SHA1',
                            'sha224', 'SHA224', 'sha256', 'SHA256',
                            'sha384', 'SHA384', 'sha512', 'SHA512')

    @pytest.mark.parametrize("hash", supported_hash_names)
    def test_hash_array(self, hashlib, hash):
        a = array.array("b", range(10))
        c = hashlib.new(hash)
        c.update(a)
        c.hexdigest()

    def test_unknown_hash(self, hashlib):
        with pytest.raises(ValueError):
            hashlib.new('spam spam spam spam spam')

    def test_large_update(self, hashlib):
        aas = b'a' * 128
        bees = b'b' * 127
        cees = b'c' * 126
        abcs = aas + bees + cees

        for name in self.supported_hash_names:
            m1 = hashlib.new(name)
            m1.update(aas)
            m1.update(bees)
            m1.update(cees)

            m2 = hashlib.new(name)
            m2.update(abcs)
            assert m1.digest() == m2.digest()

            m3 = hashlib.new(name, abcs)
            assert m1.digest() == m3.digest()

    def check(self, hashlib, name, data, digest):
        computed = hashlib.new(name, data).hexdigest()
        assert computed == digest

    def test_case_md5_0(self, hashlib):
        self.check(hashlib, 'md5', b'', 'd41d8cd98f00b204e9800998ecf8427e')

    def test_case_md5_1(self, hashlib):
        self.check(hashlib, 'md5', b'abc', '900150983cd24fb0d6963f7d28e17f72')

    def test_case_md5_2(self, hashlib):
        self.check(
            hashlib,
            'md5',
            b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
            'd174ab98d277d9f5a5611c2c9f419d9f'
        )

    # use the three examples from Federal Information Processing Standards
    # Publication 180-1, Secure Hash Standard,  1995 April 17
    # http://www.itl.nist.gov/div897/pubs/fip180-1.htm

    def test_case_sha1_0(self, hashlib):
        self.check(hashlib, 'sha1', b"",
                   "da39a3ee5e6b4b0d3255bfef95601890afd80709")

    def test_case_sha1_1(self, hashlib):
        self.check(hashlib, 'sha1', b"abc",
                   "a9993e364706816aba3e25717850c26c9cd0d89d")

    def test_case_sha1_2(self, hashlib):
        self.check(
            hashlib,
            'sha1',
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        )

    def test_case_sha1_3(self, hashlib):
        self.check(hashlib, 'sha1', b"a" * 1000000,
                   "34aa973cd4c4daa4f61eeb2bdbad27316534016f")

    # use the examples from Federal Information Processing Standards
    # Publication 180-2, Secure Hash Standard,  2002 August 1
    # http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf

    def test_case_sha224_0(self, hashlib):
        self.check(hashlib, 'sha224', b"",
                   "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")

    def test_case_sha224_1(self, hashlib):
        self.check(hashlib, 'sha224', b"abc",
                   "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")

    def test_case_sha224_2(self, hashlib):
        self.check(hashlib, 'sha224',
                   b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                   "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525")

    def test_case_sha224_3(self, hashlib):
        self.check(hashlib, 'sha224', b"a" * 1000000,
                   "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67")

    def test_case_sha256_0(self, hashlib):
        self.check(hashlib, 'sha256', b"",
                   "e3b0c44298fc1c149afbf4c8996fb924"
                   "27ae41e4649b934ca495991b7852b855")

    def test_case_sha256_1(self, hashlib):
        self.check(hashlib, 'sha256', b"abc",
                   "ba7816bf8f01cfea414140de5dae2223"
                   "b00361a396177a9cb410ff61f20015ad")

    def test_case_sha256_2(self, hashlib):
        self.check(hashlib, 'sha256',
                   b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                   "248d6a61d20638b8e5c026930c3e6039"
                   "a33ce45964ff2167f6ecedd419db06c1")

    def test_case_sha256_3(self, hashlib):
        self.check(hashlib, 'sha256', b"a" * 1000000,
                   "cdc76e5c9914fb9281a1c7e284d73e67"
                   "f1809a48a497200e046d39ccc7112cd0")

    def test_case_sha384_0(self, hashlib):
        self.check(hashlib, 'sha384', b"",
                   "38b060a751ac96384cd9327eb1b1e36a"
                   "21fdb71114be07434c0cc7bf63f6e1da"
                   "274edebfe76f65fbd51ad2f14898b95b")

    def test_case_sha384_1(self, hashlib):
        self.check(hashlib, 'sha384', b"abc",
                   "cb00753f45a35e8bb5a03d699ac65007"
                   "272c32ab0eded1631a8b605a43ff5bed"
                   "8086072ba1e7cc2358baeca134c825a7")

    def test_case_sha384_2(self, hashlib):
        self.check(hashlib, 'sha384',
                   b"abcdefghbcdefghicdefghijdefghijk"
                   b"efghijklfghijklmghijklmnhijklmno"
                   b"ijklmnopjklmnopqklmnopqrlmnopqrs"
                   b"mnopqrstnopqrstu",
                   "09330c33f71147e83d192fc782cd1b47"
                   "53111b173b3b05d22fa08086e3b0f712"
                   "fcc7c71a557e2db966c3e9fa91746039")

    def test_case_sha384_3(self, hashlib):
        self.check(hashlib, 'sha384', b"a" * 1000000,
                   "9d0e1809716474cb086e834e310a4a1c"
                   "ed149e9c00f248527972cec5704c2a5b"
                   "07b8b3dc38ecc4ebae97ddd87f3d8985")

    def test_case_sha512_0(self, hashlib):
        self.check(hashlib, 'sha512', b"",
                   "cf83e1357eefb8bdf1542850d66d8007"
                   "d620e4050b5715dc83f4a921d36ce9ce"
                   "47d0d13c5d85f2b0ff8318d2877eec2f"
                   "63b931bd47417a81a538327af927da3e")

    def test_case_sha512_1(self, hashlib):
        self.check(hashlib, 'sha512', b"abc",
                   "ddaf35a193617abacc417349ae204131"
                   "12e6fa4e89a97ea20a9eeee64b55d39a"
                   "2192992a274fc1a836ba3c23a3feebbd"
                   "454d4423643ce80e2a9ac94fa54ca49f")

    def test_case_sha512_2(self, hashlib):
        self.check(hashlib, 'sha512',
                   b"abcdefghbcdefghicdefghijdefghijk"
                   b"efghijklfghijklmghijklmnhijklmno"
                   b"ijklmnopjklmnopqklmnopqrlmnopqrs"
                   b"mnopqrstnopqrstu",
                   "8e959b75dae313da8cf4f72814fc143f"
                   "8f7779c6eb9f7fa17299aeadb6889018"
                   "501d289e4900f7e4331b99dec4b5433a"
                   "c7d329eeb6dd26545e96e55b874be909")

    def test_case_sha512_3(self, hashlib):
        self.check(hashlib, 'sha512', b"a" * 1000000,
                   "e718483d0ce769644e2e42c7bc15b463"
                   "8e1f98b13b2044285632a803afa973eb"
                   "de0ff244877ea60a4cb0432ce577c31b"
                   "eb009c5c2c49aa2e4eadb217ad8cc09b")

    def test_threaded_hashing(self, hashlib):
        # Updating the same hash object from several threads at once
        # using data chunk sizes containing the same byte sequences.
        #
        # If the internal locks are working to prevent multiple
        # updates on the same object from running at once, the resulting
        # hash will be the same as doing it single threaded upfront.
        hasher = hashlib.sha1()
        num_threads = 5
        smallest_data = b'swineflu'
        data = smallest_data*200000
        expected_hash = hashlib.sha1(data*num_threads).hexdigest()

        def hash_in_chunks(chunk_size, event):
            index = 0
            while index < len(data):
                hasher.update(data[index:index+chunk_size])
                index += chunk_size
            event.set()

        events = []
        for threadnum in range(num_threads):
            chunk_size = len(data) // (10**threadnum)
            assert chunk_size > 0
            assert chunk_size % len(smallest_data) == 0
            event = threading.Event()
            events.append(event)
            threading.Thread(target=hash_in_chunks,
                             args=(chunk_size, event)).start()

        for event in events:
            event.wait()

        assert expected_hash == hasher.hexdigest()

    def test_update_after_finalize(self, backend):
        our_sha1 = _new_hashlib_adapter(hashes.SHA1, backend)

        for sha1 in [python_hashlib.sha1, our_sha1]:
            md = sha1()

            md.update(b"A")
            digest_1 = md.digest()
            assert digest_1

            md.update(b"B")
            digest_2 = md.digest()
            assert digest_2

            assert digest_1 != digest_2

    def test_unsupported_algorithm(self, backend, monkeypatch):
        monkeypatch.setattr(hashes, "UnsupportedDummyHash",
                            UnsupportedDummyHash, raising=False)

        hashlib = Hashlib(backend)

        with pytest.raises(ValueError):
            hashlib.new("unsupported-dummy-hash")

    def test_hmac(self, backend):
        our_sha1 = _new_hashlib_adapter(hashes.SHA1, backend)

        for sha1 in [python_hashlib.sha1, our_sha1]:
            mac = hmac.new(b"test", b"message", sha1)
            mac.update(b"data")
            expected = hmac.new(b"test", b"messagedata",
                                python_hashlib.sha1).digest()
            assert mac.digest() == expected

    def test_all_algorithms(self, hashlib):
        for algo in hashlib._algorithm_map:
            h = hashlib.new(algo, b"a")
            md_1 = h.digest()

            h.update(b"b")
            md_2 = h.digest()

            assert md_1 and md_2
            assert md_1 != md_2

    def test_hashlib_new_fallback(self, hashlib):
        hashlib._algorithm_map = {}

        assert hashlib.new("sha1")
        assert hashlib.new("sha1", b"")

        with pytest.raises(TypeError):
            hashlib.new("sha1", None)

    @pytest.mark.skipif(six.PY3, reason="Not Python 2")
    def test_py2_hashable_types(self, backend):
        our_sha1 = _new_hashlib_adapter(hashes.SHA1, backend)

        for sha1 in [python_hashlib.sha1, our_sha1]:
            sha1()
            sha1(b"")
            sha1(six.u(""))
            sha1(six.u("a"))
            sha1(_buffer(b""))
            sha1(array.array("b", []))

            with pytest.raises(TypeError):
                sha1(None)

            with pytest.raises(UnicodeEncodeError):
                sha1(six.u("£"))

    @pytest.mark.skipif(six.PY2, reason="Not Python 3")
    def test_py3_hashable_types(self, backend):
        our_sha1 = _new_hashlib_adapter(hashes.SHA1, backend)

        for sha1 in [python_hashlib.sha1, our_sha1]:
            sha1()
            sha1(b"")
            sha1(_buffer(b""))
            sha1(array.array("b", []))

            with pytest.raises(TypeError):
                sha1(six.u(""))

            with pytest.raises(TypeError):
                sha1(six.u("a"))

            with pytest.raises(TypeError):
                sha1(None)

            with pytest.raises(TypeError):
                sha1(six.u("£"))

    @pytest.mark.skipif(six.PY3, reason="Not Python 2")
    def test_py2_interface(self, hashlib):
        our_hashlib = hashlib

        assert hasattr(our_hashlib, "algorithms")

        for hashlib in [python_hashlib, our_hashlib]:
            assert not hasattr(hashlib, "algorithms_guaranteed")
            assert not hasattr(hashlib, "algorithms_available")

    @pytest.mark.skipif(six.PY2, reason="Not Python 3")
    def test_py3_interface(self, hashlib):
        our_hashlib = hashlib

        for hashlib in [python_hashlib, our_hashlib]:
            assert not hasattr(hashlib, "algorithms")
            assert hasattr(hashlib, "algorithms_guaranteed")
            assert hasattr(hashlib, "algorithms_available")

    def test_buffer(self, backend):
        our_sha1 = _new_hashlib_adapter(hashes.SHA1, backend)

        for sha1 in [python_hashlib.sha1, our_sha1]:
            msg = _buffer(b"test")
            md = sha1(msg)
            expected = 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'
            assert md.hexdigest() == expected

    def test_digest_type(self, backend):
        our_sha1 = _new_hashlib_adapter(hashes.SHA1, backend)

        for sha1 in [python_hashlib.sha1, our_sha1]:
            md = sha1().digest()
            assert isinstance(md, six.binary_type)
            assert isinstance(python_hashlib.sha1().digest(), six.binary_type)

    def test_hexdigest_type(self, backend):
        our_sha1 = _new_hashlib_adapter(hashes.SHA1, backend)

        for sha1 in [python_hashlib.sha1, our_sha1]:
            md = sha1().hexdigest()
            assert isinstance(md, str)
            assert isinstance(python_hashlib.sha1().hexdigest(), str)
