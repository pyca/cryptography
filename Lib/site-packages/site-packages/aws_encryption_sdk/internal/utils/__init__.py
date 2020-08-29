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
"""Helper utility functions for AWS Encryption SDK."""
import io
import logging
import os

import six

import aws_encryption_sdk.internal.defaults
from aws_encryption_sdk.exceptions import InvalidDataKeyError, SerializationError, UnknownIdentityError
from aws_encryption_sdk.identifiers import ContentAADString, ContentType
from aws_encryption_sdk.internal.str_ops import to_bytes
from aws_encryption_sdk.structures import EncryptedDataKey

from .streams import InsistentReaderBytesIO

_LOGGER = logging.getLogger(__name__)


def content_type(frame_length):
    """Returns the appropriate content type based on the frame length.

    :param int frame_length: Message frame length
    :returns: Appropriate content type based on frame length
    :rtype: aws_encryption_sdk.identifiers.ContentType
    """
    if frame_length == 0:
        return ContentType.NO_FRAMING
    else:
        return ContentType.FRAMED_DATA


def validate_frame_length(frame_length, algorithm):
    """Validates that frame length is within the defined limits and is compatible with the selected algorithm.

    :param int frame_length: Frame size in bytes
    :param algorithm: Algorithm to use for encryption
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :raises SerializationError: if frame size is negative or not a multiple of the algorithm block size
    :raises SerializationError: if frame size is larger than the maximum allowed frame size
    """
    if frame_length < 0 or frame_length % algorithm.encryption_algorithm.block_size != 0:
        raise SerializationError(
            "Frame size must be a non-negative multiple of the block size of the crypto algorithm: {block_size}".format(
                block_size=algorithm.encryption_algorithm.block_size
            )
        )
    if frame_length > aws_encryption_sdk.internal.defaults.MAX_FRAME_SIZE:
        raise SerializationError(
            "Frame size too large: {frame} > {max}".format(
                frame=frame_length, max=aws_encryption_sdk.internal.defaults.MAX_FRAME_SIZE
            )
        )


def message_id():
    """Generates a new message ID.

    :returns: Message ID
    :rtype: bytes
    """
    return os.urandom(aws_encryption_sdk.internal.defaults.MESSAGE_ID_LENGTH)


def get_aad_content_string(content_type, is_final_frame):
    """Prepares the appropriate Body AAD Value for a message body.

    :param content_type: Defines the type of content for which to prepare AAD String
    :type content_type: aws_encryption_sdk.identifiers.ContentType
    :param bool is_final_frame: Boolean stating whether this is the final frame in a body
    :returns: Appropriate AAD Content String
    :rtype: bytes
    :raises UnknownIdentityError: if unknown content type
    """
    if content_type == ContentType.NO_FRAMING:
        aad_content_string = ContentAADString.NON_FRAMED_STRING_ID
    elif content_type == ContentType.FRAMED_DATA:
        if is_final_frame:
            aad_content_string = ContentAADString.FINAL_FRAME_STRING_ID
        else:
            aad_content_string = ContentAADString.FRAME_STRING_ID
    else:
        raise UnknownIdentityError("Unhandled content type")
    return aad_content_string


def prepare_data_keys(primary_master_key, master_keys, algorithm, encryption_context):
    """Prepares a DataKey to be used for encrypting message and list
    of EncryptedDataKey objects to be serialized into header.

    :param primary_master_key: Master key with which to generate the encryption data key
    :type primary_master_key: aws_encryption_sdk.key_providers.base.MasterKey
    :param master_keys: All master keys with which to encrypt data keys
    :type master_keys: list of :class:`aws_encryption_sdk.key_providers.base.MasterKey`
    :param algorithm: Algorithm to use for encryption
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param dict encryption_context: Encryption context to use when generating data key
    :rtype: tuple containing :class:`aws_encryption_sdk.structures.DataKey`
        and set of :class:`aws_encryption_sdk.structures.EncryptedDataKey`
    """
    encrypted_data_keys = set()
    encrypted_data_encryption_key = None
    data_encryption_key = primary_master_key.generate_data_key(algorithm, encryption_context)
    _LOGGER.debug("encryption data generated with master key: %s", data_encryption_key.key_provider)
    for master_key in master_keys:
        # Don't re-encrypt the encryption data key; we already have the ciphertext
        if master_key is primary_master_key:
            encrypted_data_encryption_key = EncryptedDataKey(
                key_provider=data_encryption_key.key_provider, encrypted_data_key=data_encryption_key.encrypted_data_key
            )
            encrypted_data_keys.add(encrypted_data_encryption_key)
            continue
        encrypted_key = master_key.encrypt_data_key(
            data_key=data_encryption_key, algorithm=algorithm, encryption_context=encryption_context
        )
        encrypted_data_keys.add(encrypted_key)
        _LOGGER.debug("encryption key encrypted with master key: %s", master_key.key_provider)
    return data_encryption_key, encrypted_data_keys


def prep_stream_data(data):
    """Take an input and prepare it for use as a stream.

    :param data: Input data
    :returns: Prepared stream
    :rtype: InsistentReaderBytesIO
    """
    if isinstance(data, (six.string_types, six.binary_type)):
        stream = io.BytesIO(to_bytes(data))
    else:
        stream = data

    return InsistentReaderBytesIO(stream)


def source_data_key_length_check(source_data_key, algorithm):
    """Validates that the supplied source_data_key's data_key is the
    correct length for the supplied algorithm's kdf_input_len value.

    :param source_data_key: Source data key object received from MasterKey decrypt or generate data_key methods
    :type source_data_key: :class:`aws_encryption_sdk.structures.RawDataKey`
        or :class:`aws_encryption_sdk.structures.DataKey`
    :param algorithm: Algorithm object which directs how this data key will be used
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :raises InvalidDataKeyError: if data key length does not match required kdf input length
    """
    if len(source_data_key.data_key) != algorithm.kdf_input_len:
        raise InvalidDataKeyError(
            "Invalid Source Data Key length {actual} for algorithm required: {required}".format(
                actual=len(source_data_key.data_key), required=algorithm.kdf_input_len
            )
        )
