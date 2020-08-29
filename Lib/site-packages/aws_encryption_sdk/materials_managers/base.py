# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Base class interface for crypto material managers."""
import abc

import six


@six.add_metaclass(abc.ABCMeta)
class CryptoMaterialsManager(object):
    """Parent interface for crypto material manager classes.

    .. versionadded:: 1.3.0
    """

    @abc.abstractmethod
    def get_encryption_materials(self, request):
        """Provides encryption materials appropriate for the request.

        .. note::
            Must be implemented by specific CryptoMaterialsManager implementations.

        :param request: encryption materials request
        :type request: aws_encryption_sdk.materials_managers.EncryptionMaterialsRequest
        :returns: encryption materials
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """

    @abc.abstractmethod
    def decrypt_materials(self, request):
        """Provides decryption materials appropriate for the request.

        .. note::
            Must be implemented by specific CryptoMaterialsManager implementations.

        :param request: decrypt materials request
        :type request: aws_encryption_sdk.materials_managers.DecryptionMaterialsRequest
        :returns: decryption materials
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """
