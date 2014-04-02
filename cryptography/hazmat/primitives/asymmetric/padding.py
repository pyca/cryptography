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

import warnings

import six

from cryptography import exceptions, utils
from cryptography.hazmat.primitives import interfaces


@utils.register_interface(interfaces.AsymmetricPadding)
class PKCS1v15(object):
    name = "EMSA-PKCS1-v1_5"


@utils.register_interface(interfaces.AsymmetricPadding)
class PSS(object):
    MAX_LENGTH = object()
    name = "EMSA-PSS"

    def __init__(self, mgf, salt_length=None):
        self._mgf = mgf

        if salt_length is None:
            warnings.warn(
                "salt_length is deprecated on MGF1 and should be added via the"
                " PSS constructor.",
                exceptions.DeprecatedIn04
            )
        else:
            if (not isinstance(salt_length, six.integer_types) and
                    salt_length is not self.MAX_LENGTH):
                raise TypeError("salt_length must be an integer")

            if salt_length is not self.MAX_LENGTH and salt_length < 0:
                raise ValueError("salt_length must be zero or greater")

        if salt_length is None and self._mgf._salt_length is None:
            raise ValueError("You must supply salt_length")

        self._salt_length = salt_length


class MGF1(object):
    MAX_LENGTH = object()

    def __init__(self, algorithm, salt_length=None):
        if not isinstance(algorithm, interfaces.HashAlgorithm):
            raise TypeError("Expected instance of interfaces.HashAlgorithm.")

        self._algorithm = algorithm

        if salt_length is not None:
            warnings.warn(
                "salt_length is deprecated on MGF1 and should be passed to "
                "the PSS constructor instead.",
                exceptions.DeprecatedIn04
            )
            if (not isinstance(salt_length, six.integer_types) and
                    salt_length is not self.MAX_LENGTH):
                raise TypeError("salt_length must be an integer")

            if salt_length is not self.MAX_LENGTH and salt_length < 0:
                raise ValueError("salt_length must be zero or greater")

        self._salt_length = salt_length
