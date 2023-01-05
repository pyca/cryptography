# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import base64
import os

import pytest

from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
)
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    KeySerializationEncryption,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_ssh_private_key,
    load_ssh_public_key,
    ssh,
)

from ...doubles import DummyKeySerializationEncryption
from ...utils import load_vectors_from_file, raises_unsupported_algorithm


class TestOpenSSHSerialization:
    @pytest.mark.parametrize(
        ("key_file", "cert_file"),
        [
            ("rsa-psw.key.pub", None),
            ("rsa-nopsw.key.pub", "rsa-nopsw.key-cert.pub"),
            ("dsa-psw.key.pub", None),
            ("dsa-nopsw.key.pub", "dsa-nopsw.key-cert.pub"),
            ("ecdsa-psw.key.pub", None),
            ("ecdsa-nopsw.key.pub", "ecdsa-nopsw.key-cert.pub"),
            ("ed25519-psw.key.pub", None),
            ("ed25519-nopsw.key.pub", "ed25519-nopsw.key-cert.pub"),
        ],
    )
    def test_load_ssh_public_key(self, key_file, cert_file, backend):
        if "ed25519" in key_file and not backend.ed25519_supported():
            pytest.skip("Requires OpenSSL with Ed25519 support")

        # normal public key
        pub_data = load_vectors_from_file(
            os.path.join("asymmetric", "OpenSSH", key_file),
            lambda f: f.read(),
            mode="rb",
        )
        public_key = load_ssh_public_key(pub_data, backend)
        nocomment_data = b" ".join(pub_data.split()[:2])
        assert (
            public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
            == nocomment_data
        )

        self.run_partial_pubkey(pub_data, backend)

        # parse public key with ssh certificate
        if cert_file:
            cert_data = load_vectors_from_file(
                os.path.join("asymmetric", "OpenSSH", cert_file),
                lambda f: f.read(),
                mode="rb",
            )
            cert_key = load_ssh_public_key(cert_data, backend)
            assert (
                cert_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
                == nocomment_data
            )

            # try with more spaces
            cert_data = b" \t ".join(cert_data.split())
            cert_key = load_ssh_public_key(cert_data, backend)
            assert (
                cert_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
                == nocomment_data
            )

            self.run_partial_pubkey(cert_data, backend)

    def run_partial_pubkey(self, pubdata, backend):
        parts = pubdata.split()
        raw = base64.b64decode(parts[1])
        for i in range(1, len(raw)):
            frag = base64.b64encode(raw[:i])
            new_pub = b" ".join([parts[0], frag])
            with pytest.raises(ValueError):
                load_ssh_public_key(new_pub, backend)

    @pytest.mark.parametrize(
        ("key_file",),
        [
            ("rsa-nopsw.key",),
            ("rsa-psw.key",),
            ("dsa-nopsw.key",),
            ("dsa-psw.key",),
            ("ecdsa-nopsw.key",),
            ("ecdsa-psw.key",),
            ("ed25519-nopsw.key",),
            ("ed25519-psw.key",),
        ],
    )
    def test_load_ssh_private_key(self, key_file, backend):
        if "ed25519" in key_file and not backend.ed25519_supported():
            pytest.skip("Requires OpenSSL with Ed25519 support")
        if "-psw" in key_file and not ssh._bcrypt_supported:
            pytest.skip("Requires bcrypt module")

        # read public and private key from ssh-keygen
        priv_data = load_vectors_from_file(
            os.path.join("asymmetric", "OpenSSH", key_file),
            lambda f: f.read(),
            mode="rb",
        )
        pub_data = load_vectors_from_file(
            os.path.join("asymmetric", "OpenSSH", key_file + ".pub"),
            lambda f: f.read(),
            mode="rb",
        )
        nocomment_data = b" ".join(pub_data.split()[:2])

        # load and compare
        password = None
        if "-psw" in key_file:
            password = b"password"
        private_key = load_ssh_private_key(priv_data, password, backend)
        assert (
            private_key.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            )
            == nocomment_data
        )

        # bytearray
        private_key = load_ssh_private_key(
            bytearray(priv_data), password, backend
        )
        assert (
            private_key.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            )
            == nocomment_data
        )

        # memoryview(bytes)
        private_key = load_ssh_private_key(
            memoryview(priv_data), password, backend
        )
        assert (
            private_key.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            )
            == nocomment_data
        )

        # memoryview(bytearray)
        private_key = load_ssh_private_key(
            memoryview(bytearray(priv_data)), password, backend
        )
        assert (
            private_key.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            )
            == nocomment_data
        )

        # serialize with own code and reload
        encryption: KeySerializationEncryption = NoEncryption()
        if password:
            encryption = BestAvailableEncryption(password)
        priv_data2 = private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.OpenSSH,
            encryption,
        )
        private_key2 = load_ssh_private_key(priv_data2, password, backend)
        assert (
            private_key2.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            )
            == nocomment_data
        )

        # make sure multi-line base64 is used
        maxline = max(map(len, priv_data2.split(b"\n")))
        assert maxline < 80

    @pytest.mark.supported(
        only_if=lambda backend: ssh._bcrypt_supported,
        skip_message="Requires that bcrypt exists",
    )
    def test_bcrypt_encryption(self, backend):
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        pub1 = private_key.public_key().public_bytes(
            Encoding.OpenSSH, PublicFormat.OpenSSH
        )

        for psw in (
            b"1",
            b"1234",
            b"1234" * 4,
            b"x" * 72,
        ):
            # BestAvailableEncryption does not handle bytes-like?
            best = BestAvailableEncryption(psw)
            encdata = private_key.private_bytes(
                Encoding.PEM, PrivateFormat.OpenSSH, best
            )
            decoded_key = load_ssh_private_key(encdata, psw, backend)
            pub2 = decoded_key.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            )
            assert pub1 == pub2

            # bytearray
            decoded_key2 = load_ssh_private_key(
                bytearray(encdata), psw, backend
            )
            pub2 = decoded_key2.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            )
            assert pub1 == pub2

            # memoryview(bytes)
            decoded_key2 = load_ssh_private_key(
                memoryview(encdata), psw, backend
            )
            pub2 = decoded_key2.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            )
            assert pub1 == pub2

            # memoryview(bytearray)
            decoded_key2 = load_ssh_private_key(
                memoryview(bytearray(encdata)), psw, backend
            )
            pub2 = decoded_key2.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            )
            assert pub1 == pub2

            with pytest.raises(ValueError):
                decoded_key = load_ssh_private_key(encdata, None, backend)
            with pytest.raises(ValueError):
                decoded_key = load_ssh_private_key(encdata, b"wrong", backend)

    @pytest.mark.supported(
        only_if=lambda backend: not ssh._bcrypt_supported,
        skip_message="Requires that bcrypt is missing",
    )
    def test_missing_bcrypt(self, backend):
        priv_data = load_vectors_from_file(
            os.path.join("asymmetric", "OpenSSH", "ecdsa-psw.key"),
            lambda f: f.read(),
            mode="rb",
        )
        with raises_unsupported_algorithm(None):
            load_ssh_private_key(priv_data, b"password", backend)

        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        with raises_unsupported_algorithm(None):
            private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.OpenSSH,
                BestAvailableEncryption(b"x"),
            )

    def test_fraglist_corners(self):
        f = ssh._FragList()
        with pytest.raises(ValueError):
            f.put_mpint(-1)
        f.put_mpint(0)
        f.put_mpint(0x80)
        assert f.tobytes() == b"\0\0\0\0" + b"\0\0\0\x02" + b"\0\x80"

    def make_file(
        self,
        magic=b"openssh-key-v1\0",
        ciphername=b"none",
        kdfname=b"none",
        kdfoptions=b"",
        nkeys=1,
        pub_type=b"ecdsa-sha2-nistp256",
        pub_fields=(
            b"nistp256",
            b"\x04" * 65,
        ),
        priv_type=None,
        priv_fields=(b"nistp256", b"\x04" * 65, b"\x7F" * 32),
        comment=b"comment",
        checkval1=b"1234",
        checkval2=b"1234",
        pad=None,
        header=b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
        footer=b"-----END OPENSSH PRIVATE KEY-----\n",
        cut=8192,
    ):
        """Create private key file"""
        if not priv_type:
            priv_type = pub_type

        pub = ssh._FragList()
        for elem in (pub_type,) + pub_fields:
            pub.put_sshstr(elem)

        secret = ssh._FragList([checkval1, checkval2])
        for i in range(nkeys):
            for elem in (priv_type,) + priv_fields + (comment,):
                secret.put_sshstr(elem)

        if pad is None:
            pad_len = 8 - (secret.size() % 8)
            pad = bytearray(range(1, 1 + pad_len))
        secret.put_raw(pad)

        main = ssh._FragList([magic])
        main.put_sshstr(ciphername)
        main.put_sshstr(kdfname)
        main.put_sshstr(kdfoptions)
        main.put_u32(nkeys)
        for i in range(nkeys):
            main.put_sshstr(pub)
        main.put_sshstr(secret)

        res = main.tobytes()
        return ssh._ssh_pem_encode(res[:cut], header, footer)

    def test_ssh_make_file(self, backend):
        # check if works by default
        data = self.make_file()
        key = load_ssh_private_key(data, None, backend)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_load_ssh_private_key_errors(self, backend):
        # bad kdf
        data = self.make_file(kdfname=b"unknown", ciphername=b"aes256-ctr")
        with raises_unsupported_algorithm(None):
            load_ssh_private_key(data, None, backend)

        # bad cipher
        data = self.make_file(ciphername=b"unknown", kdfname=b"bcrypt")
        with raises_unsupported_algorithm(None):
            load_ssh_private_key(data, None, backend)

        # bad magic
        data = self.make_file(magic=b"unknown")
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

        # too few keys
        data = self.make_file(nkeys=0)
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

        # too many keys
        data = self.make_file(nkeys=2)
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

    def test_ssh_errors_bad_values(self, backend):
        # bad curve
        data = self.make_file(pub_type=b"ecdsa-sha2-nistp444")
        with raises_unsupported_algorithm(None):
            load_ssh_private_key(data, None, backend)

        # curve mismatch
        data = self.make_file(priv_type=b"ecdsa-sha2-nistp384")
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

        # invalid bigint
        data = self.make_file(
            priv_fields=(b"nistp256", b"\x04" * 65, b"\x80" * 32)
        )
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

    def test_ssh_errors_pubpriv_mismatch(self, backend):
        # ecdsa public-private mismatch
        data = self.make_file(
            pub_fields=(
                b"nistp256",
                b"\x04" + b"\x05" * 64,
            )
        )
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

        # rsa public-private mismatch
        data = self.make_file(
            pub_type=b"ssh-rsa",
            pub_fields=(b"x" * 32,) * 2,
            priv_fields=(b"z" * 32,) * 6,
        )
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

        # dsa public-private mismatch
        data = self.make_file(
            pub_type=b"ssh-dss",
            pub_fields=(b"x" * 32,) * 4,
            priv_fields=(b"z" * 32,) * 5,
        )
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

        # ed25519 public-private mismatch
        sk = b"x" * 32
        pk1 = b"y" * 32
        pk2 = b"z" * 32
        data = self.make_file(
            pub_type=b"ssh-ed25519",
            pub_fields=(pk1,),
            priv_fields=(
                pk1,
                sk + pk2,
            ),
        )
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)
        data = self.make_file(
            pub_type=b"ssh-ed25519",
            pub_fields=(pk1,),
            priv_fields=(
                pk2,
                sk + pk1,
            ),
        )
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

    def test_ssh_errors_bad_wrapper(self, backend):
        # wrong header
        data = self.make_file(header=b"-----BEGIN RSA PRIVATE KEY-----\n")
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

        # wring footer
        data = self.make_file(footer=b"-----END RSA PRIVATE KEY-----\n")
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

    def test_ssh_no_padding(self, backend):
        # no padding must work, if data is on block boundary
        data = self.make_file(pad=b"", comment=b"")
        key = load_ssh_private_key(data, None, backend)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

        # no padding with right last byte
        data = self.make_file(pad=b"", comment=b"\x08" * 8)
        key = load_ssh_private_key(data, None, backend)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

        # avoid unexpected padding removal
        data = self.make_file(pad=b"", comment=b"1234\x01\x02\x03\x04")
        key = load_ssh_private_key(data, None, backend)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

        # bad padding with right size
        data = self.make_file(pad=b"\x08" * 8, comment=b"")
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

    def test_ssh_errors_bad_secrets(self, backend):
        # checkval mismatch
        data = self.make_file(checkval2=b"4321")
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

        # bad padding, correct=1
        data = self.make_file(pad=b"\x01\x02")
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)
        data = self.make_file(pad=b"")
        with pytest.raises(ValueError):
            load_ssh_private_key(data, None, backend)

    @pytest.mark.supported(
        only_if=lambda backend: backend.elliptic_curve_supported(
            ec.SECP192R1()
        ),
        skip_message="Requires backend support for ec.SECP192R1",
    )
    def test_serialize_ssh_private_key_errors_bad_curve(self, backend):
        private_key = ec.generate_private_key(ec.SECP192R1(), backend)
        with pytest.raises(ValueError):
            private_key.private_bytes(
                Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
            )

    def test_serialize_ssh_private_key_errors(self, backend):
        # bad encoding
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        with pytest.raises(ValueError):
            private_key.private_bytes(
                Encoding.DER, PrivateFormat.OpenSSH, NoEncryption()
            )

        # bad object type
        with pytest.raises(ValueError):
            ssh._serialize_ssh_private_key(
                object(),  # type:ignore[arg-type]
                b"",
                NoEncryption(),
            )

        private_key = ec.generate_private_key(ec.SECP256R1(), backend)

        # unknown encryption class
        with pytest.raises(ValueError):
            private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.OpenSSH,
                DummyKeySerializationEncryption(),
            )

    @pytest.mark.supported(
        only_if=lambda backend: ssh._bcrypt_supported,
        skip_message="Requires that bcrypt exists",
    )
    @pytest.mark.parametrize(
        "password",
        (
            b"1234",
            b"p@ssw0rd",
            b"x" * 100,
        ),
    )
    @pytest.mark.parametrize(
        "kdf_rounds",
        [
            1,
            10,
            30,
        ],
    )
    def test_serialize_ssh_private_key_with_password(
        self, password, kdf_rounds, backend
    ):
        original_key = ec.generate_private_key(ec.SECP256R1(), backend)
        encoded_key_data = original_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.OpenSSH,
            (
                PrivateFormat.OpenSSH.encryption_builder()
                .kdf_rounds(kdf_rounds)
                .build(password)
            ),
        )

        decoded_key = load_ssh_private_key(
            data=encoded_key_data,
            password=password,
            backend=backend,
        )

        original_public_key = original_key.public_key().public_bytes(
            Encoding.OpenSSH, PublicFormat.OpenSSH
        )

        decoded_public_key = decoded_key.public_key().public_bytes(
            Encoding.OpenSSH, PublicFormat.OpenSSH
        )

        assert original_public_key == decoded_public_key

    @pytest.mark.supported(
        only_if=lambda backend: backend.dsa_supported(),
        skip_message="Does not support DSA.",
    )
    @pytest.mark.parametrize(
        ("key_path", "supported"),
        [
            (["Traditional_OpenSSL_Serialization", "dsa.1024.pem"], True),
            (["Traditional_OpenSSL_Serialization", "dsa.2048.pem"], False),
            (["Traditional_OpenSSL_Serialization", "dsa.3072.pem"], False),
        ],
    )
    def test_dsa_private_key_sizes(self, key_path, supported, backend):
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda pemfile: load_pem_private_key(
                pemfile.read(), None, backend
            ),
            mode="rb",
        )
        assert isinstance(key, dsa.DSAPrivateKey)
        if supported:
            res = key.private_bytes(
                Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
            )
            assert isinstance(res, bytes)
        else:
            with pytest.raises(ValueError):
                key.private_bytes(
                    Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
                )
