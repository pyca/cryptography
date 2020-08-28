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
"""Contains data key helper functions."""
import logging
import struct

from cryptography.hazmat.backends import default_backend

_LOGGER = logging.getLogger(__name__)


def derive_data_encryption_key(source_key, algorithm, message_id):
    """Derives the data encryption key using the defined algorithm.

    :param bytes source_key: Raw source key
    :param algorithm: Algorithm used to encrypt this body
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes message_id: Message ID
    :returns: Derived data encryption key
    :rtype: bytes
    """
    key = source_key
    if algorithm.kdf_type is not None:
        key = algorithm.kdf_type(
            algorithm=algorithm.kdf_hash_type(),
            length=algorithm.data_key_len,
            salt=None,
            info=struct.pack(">H16s", algorithm.algorithm_id, message_id),
            backend=default_backend(),
        ).derive(source_key)
    return key
