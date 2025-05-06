# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import base64
import binascii
import os

import pytest

from cryptography.exceptions import AlreadyFinalized, InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from tests.utils import (
    load_nist_vectors,
    load_vectors_from_file,
    raises_unsupported_algorithm,
)

vectors = load_vectors_from_file(
    os.path.join("KDF", "argon2id.txt"), load_nist_vectors
)


@pytest.mark.supported(
    only_if=lambda backend: not backend.argon2_supported(),
    skip_message="Supports argon2 so can't test unsupported path",
)
def test_unsupported_backend(backend):
    with raises_unsupported_algorithm(None):
        Argon2id(
            salt=b"salt" * 2, length=32, iterations=1, lanes=1, memory_cost=32
        )


@pytest.mark.supported(
    only_if=lambda backend: backend.argon2_supported(),
    skip_message="Argon2id not supported by this version of OpenSSL",
)
class TestArgon2id:
    @pytest.mark.parametrize("params", vectors)
    def test_derive(self, params, backend):
        salt = binascii.unhexlify(params["salt"])
        ad = binascii.unhexlify(params["ad"]) if "ad" in params else None
        secret = (
            binascii.unhexlify(params["secret"])
            if "secret" in params
            else None
        )
        length = int(params["length"])
        iterations = int(params["iter"])
        lanes = int(params["lanes"])
        memory_cost = int(params["memcost"])
        password = binascii.unhexlify(params["pass"])
        derived_key = params["output"].lower()

        argon2id = Argon2id(
            salt=salt,
            length=length,
            iterations=iterations,
            lanes=lanes,
            memory_cost=memory_cost,
            ad=ad,
            secret=secret,
        )
        assert binascii.hexlify(argon2id.derive(password)) == derived_key

    def test_invalid_types(self, backend):
        with pytest.raises(TypeError):
            Argon2id(
                salt="notbytes",  # type: ignore[arg-type]
                length=32,
                iterations=1,
                lanes=1,
                memory_cost=32,
                ad=None,
                secret=None,
            )

        with pytest.raises(TypeError):
            Argon2id(
                salt=b"b" * 8,
                length=32,
                iterations=1,
                lanes=1,
                memory_cost=32,
                ad="string",  # type: ignore[arg-type]
                secret=None,
            )

        with pytest.raises(TypeError):
            Argon2id(
                salt=b"b" * 8,
                length=32,
                iterations=1,
                lanes=1,
                memory_cost=32,
                ad=None,
                secret="string",  # type: ignore[arg-type]
            )

    @pytest.mark.parametrize(
        "params",
        [
            (b"b" * 7, 3, 1, 1, 32),  # salt < 8
            (b"b" * 8, 3, 1, 1, 32),  # length < 4
            (b"b" * 8, 32, 0, 1, 32),  # iterations < 1
            (b"b" * 8, 32, 1, 0, 32),  # lanes < 1
            (b"b" * 8, 32, 1, 1, 7),  # memory_cost < 8 * lanes
            (b"b" * 8, 32, 1, 32, 200),  # memory_cost < 8 * lanes
        ],
    )
    def test_invalid_values(self, params, backend):
        (salt, length, iterations, lanes, memory_cost) = params
        with pytest.raises(ValueError):
            Argon2id(
                salt=salt,
                length=length,
                iterations=iterations,
                lanes=lanes,
                memory_cost=memory_cost,
            )

    def test_already_finalized(self, backend):
        argon2id = Argon2id(
            salt=b"salt" * 2, length=32, iterations=1, lanes=1, memory_cost=32
        )
        argon2id.derive(b"password")
        with pytest.raises(AlreadyFinalized):
            argon2id.derive(b"password")

    def test_already_finalized_verify(self, backend):
        argon2id = Argon2id(
            salt=b"salt" * 2, length=32, iterations=1, lanes=1, memory_cost=32
        )
        digest = argon2id.derive(b"password")
        with pytest.raises(AlreadyFinalized):
            argon2id.verify(b"password", digest)

    @pytest.mark.parametrize("digest", [b"invalidkey", b"0" * 32])
    def test_invalid_verify(self, digest, backend):
        argon2id = Argon2id(
            salt=b"salt" * 2, length=32, iterations=1, lanes=1, memory_cost=32
        )
        with pytest.raises(InvalidKey):
            argon2id.verify(b"password", digest)

    def test_verify(self, backend):
        argon2id = Argon2id(
            salt=b"salt" * 2,
            length=32,
            iterations=1,
            lanes=1,
            memory_cost=32,
            ad=None,
            secret=None,
        )
        digest = argon2id.derive(b"password")
        Argon2id(
            salt=b"salt" * 2, length=32, iterations=1, lanes=1, memory_cost=32
        ).verify(b"password", digest)

    def test_derive_phc_encoded(self, backend):
        # Test that we can generate a PHC formatted string
        argon2id = Argon2id(
            salt=b"0" * 8,
            length=32,
            iterations=2,
            lanes=2,
            memory_cost=64,
        )
        encoded = argon2id.derive_phc_encoded(b"password")

        # Verify the general format is correct
        assert encoded == (
            "$argon2id$v=19$m=64,t=2,p=2$"
            "MDAwMDAwMDA$"
            "jFn1qYAgmfVKFWVeUGQcVK4d8RSiQJFTS7R7VII+fRk"
        )

    def test_verify_phc_encoded(self):
        # First generate a PHC string
        argon2id = Argon2id(
            salt=b"0" * 8,
            length=32,
            iterations=1,
            lanes=1,
            memory_cost=32,
        )
        encoded = argon2id.derive_phc_encoded(b"password")

        Argon2id.verify_phc_encoded(b"password", encoded)
        Argon2id(
            salt=b"0" * 8,
            length=32,
            iterations=1,
            lanes=1,
            memory_cost=32,
        ).verify(b"password", base64.b64decode(encoded.split("$")[-1] + "="))

        with pytest.raises(InvalidKey):
            Argon2id.verify_phc_encoded(b"wrong_password", encoded)

    def test_verify_phc_vector(self):
        # From https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#example
        Argon2id.verify_phc_encoded(
            b"hunter2",
            "$argon2id$v=19$m=65536,t=2,p=1$gZiV/M1gPc22ElAH/Jh1Hw$CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno",
            secret=b"pepper",
        )

    def test_verify_phc_encoded_invalid_format(self):
        # Totally invalid string
        with pytest.raises(InvalidKey):
            Argon2id.verify_phc_encoded(b"password", "not-a-valid-format")

        # Invalid algorithm
        with pytest.raises(InvalidKey):
            Argon2id.verify_phc_encoded(
                b"password", "$argon2i$v=19$m=32,t=1,p=1$c2FsdHNhbHQ$hash"
            )

        # Invalid version
        with pytest.raises(InvalidKey):
            Argon2id.verify_phc_encoded(
                b"password", "$argon2id$v=18$m=32,t=1,p=1$c2FsdHNhbHQ$hash"
            )

        # Missing parameters
        with pytest.raises(InvalidKey):
            Argon2id.verify_phc_encoded(
                b"password", "$argon2id$v=19$m=32,t=1$c2FsdHNhbHQ$hash"
            )

        # Parameters in wrong order
        with pytest.raises(InvalidKey):
            Argon2id.verify_phc_encoded(
                b"password", "$argon2id$v=19$t=1,m=32,p=1$c2FsdHNhbHQ$hash"
            )

        # Invalid memory cost
        with pytest.raises(InvalidKey):
            Argon2id.verify_phc_encoded(
                b"password", "$argon2id$v=19$m=abc,t=1,p=1$!invalid!$hash"
            )

        # Invalid iterations
        with pytest.raises(InvalidKey):
            Argon2id.verify_phc_encoded(
                b"password", "$argon2id$v=19$m=32,t=abc,p=1$!invalid!$hash"
            )

        # Invalid lanes
        with pytest.raises(InvalidKey):
            Argon2id.verify_phc_encoded(
                b"password", "$argon2id$v=19$m=32,t=1,p=abc$!invalid!$hash"
            )

        # Invalid base64 in salt
        with pytest.raises(InvalidKey):
            Argon2id.verify_phc_encoded(
                b"password", "$argon2id$v=19$m=32,t=1,p=1$!invalid!$hash"
            )

        # Invalid base64 in hash
        with pytest.raises(InvalidKey):
            Argon2id.verify_phc_encoded(
                b"password",
                "$argon2id$v=19$m=32,t=1,p=1$c2FsdHNhbHQ$!invalid!",
            )
