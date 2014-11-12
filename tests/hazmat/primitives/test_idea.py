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
import os

import pytest

from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.tests.primitives.utils import generate_encrypt_test
from cryptography.tests.utils import load_nist_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.IDEA("\x00" * 16), modes.ECB()
    ),
    skip_message="Does not support IDEA ECB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestIDEAModeECB(object):
    test_ECB = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "IDEA"),
        ["idea-ecb.txt"],
        lambda key, **kwargs: algorithms.IDEA(binascii.unhexlify((key))),
        lambda **kwargs: modes.ECB(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.IDEA("\x00" * 16), modes.CBC("\x00" * 8)
    ),
    skip_message="Does not support IDEA CBC",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestIDEAModeCBC(object):
    test_CBC = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "IDEA"),
        ["idea-cbc.txt"],
        lambda key, **kwargs: algorithms.IDEA(binascii.unhexlify((key))),
        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv))
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.IDEA("\x00" * 16), modes.OFB("\x00" * 8)
    ),
    skip_message="Does not support IDEA OFB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestIDEAModeOFB(object):
    test_OFB = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "IDEA"),
        ["idea-ofb.txt"],
        lambda key, **kwargs: algorithms.IDEA(binascii.unhexlify((key))),
        lambda iv, **kwargs: modes.OFB(binascii.unhexlify(iv))
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.IDEA("\x00" * 16), modes.CFB("\x00" * 8)
    ),
    skip_message="Does not support IDEA CFB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestIDEAModeCFB(object):
    test_CFB = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "IDEA"),
        ["idea-cfb.txt"],
        lambda key, **kwargs: algorithms.IDEA(binascii.unhexlify((key))),
        lambda iv, **kwargs: modes.CFB(binascii.unhexlify(iv))
    )
