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

from cryptography.hazmat.backends.interfaces import HMACBackend
from cryptography.hazmat.primitives import hashes

from .utils import generate_hmac_test
from ...utils import load_hash_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.MD5()),
    skip_message="Does not support MD5",
)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHMACMD5(object):
    test_hmac_md5 = generate_hmac_test(
        load_hash_vectors,
        "HMAC",
        [
            "rfc-2202-md5.txt",
        ],
        hashes.MD5(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.SHA1()),
    skip_message="Does not support SHA1",
)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHMACSHA1(object):
    test_hmac_sha1 = generate_hmac_test(
        load_hash_vectors,
        "HMAC",
        [
            "rfc-2202-sha1.txt",
        ],
        hashes.SHA1(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.SHA224()),
    skip_message="Does not support SHA224",
)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHMACSHA224(object):
    test_hmac_sha224 = generate_hmac_test(
        load_hash_vectors,
        "HMAC",
        [
            "rfc-4231-sha224.txt",
        ],
        hashes.SHA224(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.SHA256()),
    skip_message="Does not support SHA256",
)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHMACSHA256(object):
    test_hmac_sha256 = generate_hmac_test(
        load_hash_vectors,
        "HMAC",
        [
            "rfc-4231-sha256.txt",
        ],
        hashes.SHA256(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.SHA384()),
    skip_message="Does not support SHA384",
)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHMACSHA384(object):
    test_hmac_sha384 = generate_hmac_test(
        load_hash_vectors,
        "HMAC",
        [
            "rfc-4231-sha384.txt",
        ],
        hashes.SHA384(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.SHA512()),
    skip_message="Does not support SHA512",
)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHMACSHA512(object):
    test_hmac_sha512 = generate_hmac_test(
        load_hash_vectors,
        "HMAC",
        [
            "rfc-4231-sha512.txt",
        ],
        hashes.SHA512(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.RIPEMD160()),
    skip_message="Does not support RIPEMD160",
)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHMACRIPEMD160(object):
    test_hmac_ripemd160 = generate_hmac_test(
        load_hash_vectors,
        "HMAC",
        [
            "rfc-2286-ripemd160.txt",
        ],
        hashes.RIPEMD160(),
    )
