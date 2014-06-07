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


def load_pem_traditional_openssl_private_key(data, password, backend):
    return backend.load_traditional_openssl_pem_private_key(
        data, password
    )


def load_pem_pkcs8_private_key(data, password, backend):
    return backend.load_pkcs8_pem_private_key(
        data, password
    )


def load_rsa_private_numbers(numbers, backend):
    return backend.load_rsa_private_numbers(numbers)


def load_rsa_public_numbers(numbers, backend):
    return backend.load_rsa_public_numbers(numbers)
