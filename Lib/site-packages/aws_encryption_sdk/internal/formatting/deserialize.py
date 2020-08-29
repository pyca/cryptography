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
"""Components for handling AWS Encryption SDK message deserialization."""
from __future__ import division

import io
import logging
import struct

from cryptography.exceptions import InvalidTag

from aws_encryption_sdk.exceptions import NotSupportedError, SerializationError, UnknownIdentityError
from aws_encryption_sdk.identifiers import (
    AlgorithmSuite,
    ContentType,
    ObjectType,
    SequenceIdentifier,
    SerializationVersion,
)
from aws_encryption_sdk.internal.crypto.encryption import decrypt
from aws_encryption_sdk.internal.defaults import MAX_FRAME_SIZE
from aws_encryption_sdk.internal.formatting.encryption_context import deserialize_encryption_context
from aws_encryption_sdk.internal.str_ops import to_str
from aws_encryption_sdk.internal.structures import (
    EncryptedData,
    MessageFooter,
    MessageFrameBody,
    MessageHeaderAuthentication,
)
from aws_encryption_sdk.internal.utils.streams import TeeStream
from aws_encryption_sdk.structures import EncryptedDataKey, MasterKeyInfo, MessageHeader

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import IO, Set  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

_LOGGER = logging.getLogger(__name__)


def validate_header(header, header_auth, raw_header, data_key):
    """Validates the header using the header authentication data.

    :param header: Deserialized header
    :type header: aws_encryption_sdk.structures.MessageHeader
    :param header_auth: Deserialized header auth
    :type header_auth: aws_encryption_sdk.internal.structures.MessageHeaderAuthentication
    :type stream: io.BytesIO
    :param bytes raw_header: Raw header bytes
    :param bytes data_key: Data key with which to perform validation
    :raises SerializationError: if header authorization fails
    """
    _LOGGER.debug("Starting header validation")
    try:
        decrypt(
            algorithm=header.algorithm,
            key=data_key,
            encrypted_data=EncryptedData(header_auth.iv, b"", header_auth.tag),
            associated_data=raw_header,
        )
    except InvalidTag:
        raise SerializationError("Header authorization failed")


def _verified_version_from_id(version_id):
    # type: (int) -> SerializationVersion
    """Load a message :class:`SerializationVersion` for the specified version ID.

    :param int version_id: Message format version ID
    :return: Message format version
    :rtype: SerializationVersion
    :raises NotSupportedError: if unsupported version ID is received
    """
    try:
        return SerializationVersion(version_id)
    except ValueError as error:
        raise NotSupportedError("Unsupported version {}".format(version_id), error)


def _verified_message_type_from_id(message_type_id):
    # type: (int) -> ObjectType
    """Load a message :class:`ObjectType` for the specified message type ID.

    :param int message_type_id: Message type ID
    :return: Message type
    :rtype: ObjectType
    :raises NotSupportedError: if unsupported message type ID is received
    """
    try:
        return ObjectType(message_type_id)
    except ValueError as error:
        raise NotSupportedError("Unsupported type {} discovered in data stream".format(message_type_id), error)


def _verified_algorithm_from_id(algorithm_id):
    # type: (int) -> AlgorithmSuite
    """Load a message :class:`AlgorithmSuite` for the specified algorithm suite ID.

    :param int algorithm_id: Algorithm suite ID
    :return: Algorithm suite
    :rtype: AlgorithmSuite
    :raises UnknownIdentityError: if unknown algorithm ID is received
    :raises NotSupportedError: if unsupported algorithm ID is received
    """
    try:
        algorithm_suite = AlgorithmSuite.get_by_id(algorithm_id)
    except KeyError as error:
        raise UnknownIdentityError("Unknown algorithm {}".format(algorithm_id), error)

    if not algorithm_suite.allowed:
        raise NotSupportedError("Unsupported algorithm: {}".format(algorithm_suite))

    return algorithm_suite


def _deserialize_encrypted_data_keys(stream):
    # type: (IO) -> Set[EncryptedDataKey]
    """Deserialize some encrypted data keys from a stream.

    :param stream: Stream from which to read encrypted data keys
    :return: Loaded encrypted data keys
    :rtype: set of :class:`EncryptedDataKey`
    """
    (encrypted_data_key_count,) = unpack_values(">H", stream)
    encrypted_data_keys = set([])
    for _ in range(encrypted_data_key_count):
        (key_provider_length,) = unpack_values(">H", stream)
        (key_provider_identifier,) = unpack_values(">{}s".format(key_provider_length), stream)
        (key_provider_information_length,) = unpack_values(">H", stream)
        (key_provider_information,) = unpack_values(">{}s".format(key_provider_information_length), stream)
        (encrypted_data_key_length,) = unpack_values(">H", stream)
        encrypted_data_key = stream.read(encrypted_data_key_length)
        encrypted_data_keys.add(
            EncryptedDataKey(
                key_provider=MasterKeyInfo(
                    provider_id=to_str(key_provider_identifier), key_info=key_provider_information
                ),
                encrypted_data_key=encrypted_data_key,
            )
        )
    return encrypted_data_keys


def _verified_content_type_from_id(content_type_id):
    # type: (int) -> ContentType
    """Load a message :class:`ContentType` for the specified content type ID.

    :param int content_type_id: Content type ID
    :return: Message content type
    :rtype: ContentType
    :raises UnknownIdentityError: if unknown content type ID is received
    """
    try:
        return ContentType(content_type_id)
    except ValueError as error:
        raise UnknownIdentityError("Unknown content type {}".format(content_type_id), error)


def _verified_content_aad_length(content_aad_length):
    # type: (int) -> int
    """Verify that content aad length is ``0``.

    :param int content_aad_length: Content aad length to verify
    :return: ``0``
    :rtype: int
    :raises SerializationError: if ``content_aad_length`` is not ``0``
    """
    if content_aad_length != 0:
        raise SerializationError("Content AAD length field is currently unused, its value must be always 0")

    return 0


def _verified_iv_length(iv_length, algorithm_suite):
    # type: (int, AlgorithmSuite) -> int
    """Verify an IV length for an algorithm suite.

    :param int iv_length: IV length to verify
    :param AlgorithmSuite algorithm_suite: Algorithm suite to verify against
    :return: IV length
    :rtype: int
    :raises SerializationError: if IV length does not match algorithm suite
    """
    if iv_length != algorithm_suite.iv_len:
        raise SerializationError(
            "Specified IV length ({length}) does not match algorithm IV length ({algorithm})".format(
                length=iv_length, algorithm=algorithm_suite
            )
        )

    return iv_length


def _verified_frame_length(frame_length, content_type):
    # type: (int, ContentType) -> int
    """Verify a frame length value for a message content type.

    :param int frame_length: Frame length to verify
    :param ContentType content_type: Message content type to verify against
    :return: frame length
    :rtype: int
    :raises SerializationError: if frame length is too large
    :raises SerializationError: if frame length is not zero for unframed content type
    """
    if content_type == ContentType.FRAMED_DATA and frame_length > MAX_FRAME_SIZE:
        raise SerializationError(
            "Specified frame length larger than allowed maximum: {found} > {max}".format(
                found=frame_length, max=MAX_FRAME_SIZE
            )
        )

    if content_type == ContentType.NO_FRAMING and frame_length != 0:
        raise SerializationError("Non-zero frame length found for non-framed message")

    return frame_length


def deserialize_header(stream):
    # type: (IO) -> MessageHeader
    """Deserializes the header from a source stream

    :param stream: Source data stream
    :type stream: io.BytesIO
    :returns: Deserialized MessageHeader object
    :rtype: :class:`aws_encryption_sdk.structures.MessageHeader` and bytes
    :raises NotSupportedError: if unsupported data types are found
    :raises UnknownIdentityError: if unknown data types are found
    :raises SerializationError: if IV length does not match algorithm
    """
    _LOGGER.debug("Starting header deserialization")
    tee = io.BytesIO()
    tee_stream = TeeStream(stream, tee)
    version_id, message_type_id = unpack_values(">BB", tee_stream)
    header = dict()
    header["version"] = _verified_version_from_id(version_id)
    header["type"] = _verified_message_type_from_id(message_type_id)

    algorithm_id, message_id, ser_encryption_context_length = unpack_values(">H16sH", tee_stream)

    header["algorithm"] = _verified_algorithm_from_id(algorithm_id)
    header["message_id"] = message_id

    header["encryption_context"] = deserialize_encryption_context(tee_stream.read(ser_encryption_context_length))

    header["encrypted_data_keys"] = _deserialize_encrypted_data_keys(tee_stream)

    (content_type_id,) = unpack_values(">B", tee_stream)
    header["content_type"] = _verified_content_type_from_id(content_type_id)

    (content_aad_length,) = unpack_values(">I", tee_stream)
    header["content_aad_length"] = _verified_content_aad_length(content_aad_length)

    (iv_length,) = unpack_values(">B", tee_stream)
    header["header_iv_length"] = _verified_iv_length(iv_length, header["algorithm"])

    (frame_length,) = unpack_values(">I", tee_stream)
    header["frame_length"] = _verified_frame_length(frame_length, header["content_type"])

    return MessageHeader(**header), tee.getvalue()


def deserialize_header_auth(stream, algorithm, verifier=None):
    """Deserializes a MessageHeaderAuthentication object from a source stream.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :param algorithm: The AlgorithmSuite object type contained in the header
    :type algorith: aws_encryption_sdk.identifiers.AlgorithmSuite
    :param verifier: Signature verifier object (optional)
    :type verifier: aws_encryption_sdk.internal.crypto.Verifier
    :returns: Deserialized MessageHeaderAuthentication object
    :rtype: aws_encryption_sdk.internal.structures.MessageHeaderAuthentication
    """
    _LOGGER.debug("Starting header auth deserialization")
    format_string = ">{iv_len}s{tag_len}s".format(iv_len=algorithm.iv_len, tag_len=algorithm.tag_len)
    return MessageHeaderAuthentication(*unpack_values(format_string, stream, verifier))


def deserialize_non_framed_values(stream, header, verifier=None):
    """Deserializes the IV and body length from a non-framed stream.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :param header: Deserialized header
    :type header: aws_encryption_sdk.structures.MessageHeader
    :param verifier: Signature verifier object (optional)
    :type verifier: aws_encryption_sdk.internal.crypto.Verifier
    :returns: IV and Data Length values for body
    :rtype: tuple of bytes and int
    """
    _LOGGER.debug("Starting non-framed body iv/tag deserialization")
    (data_iv, data_length) = unpack_values(">{}sQ".format(header.algorithm.iv_len), stream, verifier)
    return data_iv, data_length


def deserialize_tag(stream, header, verifier=None):
    """Deserialize the Tag value from a non-framed stream.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :param header: Deserialized header
    :type header: aws_encryption_sdk.structures.MessageHeader
    :param verifier: Signature verifier object (optional)
    :type verifier: aws_encryption_sdk.internal.crypto.Verifier
    :returns: Tag value for body
    :rtype: bytes
    """
    (data_tag,) = unpack_values(
        format_string=">{auth_len}s".format(auth_len=header.algorithm.auth_len), stream=stream, verifier=verifier
    )
    return data_tag


def deserialize_frame(stream, header, verifier=None):
    """Deserializes a frame from a body.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :param header: Deserialized header
    :type header: aws_encryption_sdk.structures.MessageHeader
    :param verifier: Signature verifier object (optional)
    :type verifier: aws_encryption_sdk.internal.crypto.Verifier
    :returns: Deserialized frame and a boolean stating if this is the final frame
    :rtype: :class:`aws_encryption_sdk.internal.structures.MessageFrameBody` and bool
    """
    _LOGGER.debug("Starting frame deserialization")
    frame_data = {}
    final_frame = False
    (sequence_number,) = unpack_values(">I", stream, verifier)
    if sequence_number == SequenceIdentifier.SEQUENCE_NUMBER_END.value:
        _LOGGER.debug("Deserializing final frame")
        (sequence_number,) = unpack_values(">I", stream, verifier)
        final_frame = True
    else:
        _LOGGER.debug("Deserializing frame sequence number %d", int(sequence_number))
    frame_data["final_frame"] = final_frame
    frame_data["sequence_number"] = sequence_number
    (frame_iv,) = unpack_values(">{iv_len}s".format(iv_len=header.algorithm.iv_len), stream, verifier)
    frame_data["iv"] = frame_iv
    if final_frame is True:
        (content_length,) = unpack_values(">I", stream, verifier)
        if content_length >= header.frame_length:
            raise SerializationError(
                "Invalid final frame length: {final} >= {normal}".format(
                    final=content_length, normal=header.frame_length
                )
            )
    else:
        content_length = header.frame_length
    (frame_content, frame_tag) = unpack_values(
        ">{content_len}s{auth_len}s".format(content_len=content_length, auth_len=header.algorithm.auth_len),
        stream,
        verifier,
    )
    frame_data["ciphertext"] = frame_content
    frame_data["tag"] = frame_tag
    return MessageFrameBody(**frame_data), final_frame


def deserialize_footer(stream, verifier=None):
    """Deserializes a footer.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :param verifier: Signature verifier object (optional)
    :type verifier: aws_encryption_sdk.internal.crypto.Verifier
    :returns: Deserialized footer
    :rtype: aws_encryption_sdk.internal.structures.MessageFooter
    :raises SerializationError: if verifier supplied and no footer found
    """
    _LOGGER.debug("Starting footer deserialization")
    signature = b""
    if verifier is None:
        return MessageFooter(signature=signature)
    try:
        (sig_len,) = unpack_values(">H", stream)
        (signature,) = unpack_values(">{sig_len}s".format(sig_len=sig_len), stream)
    except SerializationError:
        raise SerializationError("No signature found in message")
    if verifier:
        verifier.verify(signature)
    return MessageFooter(signature=signature)


def unpack_values(format_string, stream, verifier=None):
    """Helper function to unpack struct data from a stream and update the signature verifier.

    :param str format_string: Struct format string
    :param stream: Source data stream
    :type stream: io.BytesIO
    :param verifier: Signature verifier object
    :type verifier: aws_encryption_sdk.internal.crypto.Verifier
    :returns: Unpacked values
    :rtype: tuple
    """
    try:
        message_bytes = stream.read(struct.calcsize(format_string))
        if verifier:
            verifier.update(message_bytes)
        values = struct.unpack(format_string, message_bytes)
    except struct.error as error:
        raise SerializationError("Unexpected deserialization error", type(error), error.args)
    return values


def deserialize_wrapped_key(wrapping_algorithm, wrapping_key_id, wrapped_encrypted_key):
    """Extracts and deserializes EncryptedData from a Wrapped EncryptedDataKey.

    :param wrapping_algorithm: Wrapping Algorithm with which to wrap plaintext_data_key
    :type wrapping_algorithm: aws_encryption_sdk.identifiers.WrappingAlgorithm
    :param bytes wrapping_key_id: Key ID of wrapping MasterKey
    :param wrapped_encrypted_key: Raw Wrapped EncryptedKey
    :type wrapped_encrypted_key: aws_encryption_sdk.structures.EncryptedDataKey
    :returns: EncryptedData of deserialized Wrapped EncryptedKey
    :rtype: aws_encryption_sdk.internal.structures.EncryptedData
    :raises SerializationError: if wrapping_key_id does not match deserialized wrapping key id
    :raises SerializationError: if wrapping_algorithm IV length does not match deserialized IV length
    """
    if wrapping_key_id == wrapped_encrypted_key.key_provider.key_info:
        encrypted_wrapped_key = EncryptedData(iv=None, ciphertext=wrapped_encrypted_key.encrypted_data_key, tag=None)
    else:
        if not wrapped_encrypted_key.key_provider.key_info.startswith(wrapping_key_id):
            raise SerializationError("Master Key mismatch for wrapped data key")
        _key_info = wrapped_encrypted_key.key_provider.key_info[len(wrapping_key_id) :]
        try:
            tag_len, iv_len = struct.unpack(">II", _key_info[:8])
        except struct.error:
            raise SerializationError("Malformed key info: key info missing data")
        tag_len //= 8  # Tag Length is stored in bits, not bytes
        if iv_len != wrapping_algorithm.algorithm.iv_len:
            raise SerializationError("Wrapping AlgorithmSuite mismatch for wrapped data key")
        iv = _key_info[8:]
        if len(iv) != iv_len:
            raise SerializationError("Malformed key info: incomplete iv")
        ciphertext = wrapped_encrypted_key.encrypted_data_key[: -1 * tag_len]
        tag = wrapped_encrypted_key.encrypted_data_key[-1 * tag_len :]
        if not ciphertext or len(tag) != tag_len:
            raise SerializationError("Malformed key info: incomplete ciphertext or tag")
        encrypted_wrapped_key = EncryptedData(iv=iv, ciphertext=ciphertext, tag=tag)
    return encrypted_wrapped_key
