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
"""High level AWS Encryption SDK client for streaming objects."""
from __future__ import division

import abc
import io
import logging
import math

import attr
import six

import aws_encryption_sdk.internal.utils
from aws_encryption_sdk.exceptions import (
    ActionNotAllowedError,
    AWSEncryptionSDKClientError,
    CustomMaximumValueExceeded,
    NotSupportedError,
    SerializationError,
)
from aws_encryption_sdk.identifiers import Algorithm, ContentType
from aws_encryption_sdk.internal.crypto.authentication import Signer, Verifier
from aws_encryption_sdk.internal.crypto.data_keys import derive_data_encryption_key
from aws_encryption_sdk.internal.crypto.encryption import Decryptor, Encryptor, decrypt
from aws_encryption_sdk.internal.crypto.iv import non_framed_body_iv
from aws_encryption_sdk.internal.defaults import FRAME_LENGTH, LINE_LENGTH, MAX_NON_FRAMED_SIZE, TYPE, VERSION
from aws_encryption_sdk.internal.formatting.deserialize import (
    deserialize_footer,
    deserialize_frame,
    deserialize_header,
    deserialize_header_auth,
    deserialize_non_framed_values,
    deserialize_tag,
    validate_header,
)
from aws_encryption_sdk.internal.formatting.encryption_context import assemble_content_aad
from aws_encryption_sdk.internal.formatting.serialize import (
    serialize_footer,
    serialize_frame,
    serialize_header,
    serialize_header_auth,
    serialize_non_framed_close,
    serialize_non_framed_open,
)
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.materials_managers import DecryptionMaterialsRequest, EncryptionMaterialsRequest
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager
from aws_encryption_sdk.structures import MessageHeader

_LOGGER = logging.getLogger(__name__)


@attr.s(hash=True)
@six.add_metaclass(abc.ABCMeta)
class _ClientConfig(object):
    """Parent configuration object for StreamEncryptor and StreamDecryptor objects.

    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param materials_manager: `CryptoMaterialsManager` from which to obtain cryptographic materials
        (either `materials_manager` or `key_provider` required)
    :type materials_manager: aws_encryption_sdk.materials_manager.base.CryptoMaterialsManager
    :param key_provider: `MasterKeyProvider` from which to obtain data keys for encryption
        (either `materials_manager` or `key_provider` required)
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and unframed message is being written or read() is called,
            will attempt to seek() to the end of the stream and tell() to find the length of source data.
    """

    source = attr.ib(hash=True, converter=aws_encryption_sdk.internal.utils.prep_stream_data)
    materials_manager = attr.ib(
        hash=True, default=None, validator=attr.validators.optional(attr.validators.instance_of(CryptoMaterialsManager))
    )
    key_provider = attr.ib(
        hash=True, default=None, validator=attr.validators.optional(attr.validators.instance_of(MasterKeyProvider))
    )
    source_length = attr.ib(
        hash=True, default=None, validator=attr.validators.optional(attr.validators.instance_of(six.integer_types))
    )
    line_length = attr.ib(
        hash=True, default=LINE_LENGTH, validator=attr.validators.instance_of(six.integer_types)
    )  # DEPRECATED: Value is no longer configurable here.  Parameter left here to avoid breaking consumers.

    def __attrs_post_init__(self):
        """Normalize inputs to crypto material manager."""
        both_cmm_and_mkp_defined = self.materials_manager is not None and self.key_provider is not None
        neither_cmm_nor_mkp_defined = self.materials_manager is None and self.key_provider is None

        if both_cmm_and_mkp_defined or neither_cmm_nor_mkp_defined:
            raise TypeError("Exactly one of materials_manager or key_provider must be provided")
        if self.materials_manager is None:
            self.materials_manager = DefaultCryptoMaterialsManager(master_key_provider=self.key_provider)


class _EncryptionStream(io.IOBase):
    """Parent class for StreamEncryptor and StreamDecryptor classes.

    :param config: Client configuration object
    :type config: aws_encryption_sdk.streaming_client._ClientConfig
    """

    # abc.ABCMeta does not behave properly for defining abstractmethods in children of io.IOBase
    #     due to complexities in how __new__ is called (or not called) with C-module objects.
    # Leaving this here as an explanation of what is going on in __new__
    #
    # @abc.abstractmethod
    # def _read_bytes(self, b):
    #     Reads the requested number of bytes from the source stream.
    #
    #     :param int b: Number of bytes to read
    #     :returns: Processed (encrypted or decrypted) bytes from source stream
    #     :rtype: bytes
    #
    # @abc.abstractmethod
    # def _prep_message(self):
    #     Performs initial message setup.
    #
    # @abc.abstractproperty
    # def _config_class(self):
    #     Configuration class for this class

    line_length = LINE_LENGTH  # type: int
    config = None  # type: _ClientConfig
    bytes_read = None  # type: int
    output_buffer = None  # type: bytes
    _message_prepped = None  # type: bool
    source_stream = None
    _stream_length = None  # type: int

    def __new__(cls, **kwargs):
        """Perform necessary handling for _EncryptionStream instances that should be
        applied to all children.
        """
        # Patch for abstractmethod-like enforcement in io.IOBase grandchildren.
        if (
            not (hasattr(cls, "_read_bytes") and callable(cls._read_bytes))
            or not (hasattr(cls, "_prep_message") and callable(cls._read_bytes))
            or not hasattr(cls, "_config_class")
        ):
            raise TypeError("Can't instantiate abstract class {}".format(cls.__name__))

        instance = super(_EncryptionStream, cls).__new__(cls)

        config = kwargs.pop("config", None)
        if not isinstance(config, instance._config_class):  # pylint: disable=protected-access
            config = instance._config_class(**kwargs)  # pylint: disable=protected-access
        instance.config = config

        instance.bytes_read = 0
        instance.output_buffer = b""
        instance._message_prepped = False  # pylint: disable=protected-access
        instance.source_stream = instance.config.source
        instance._stream_length = instance.config.source_length  # pylint: disable=protected-access

        return instance

    @property
    def stream_length(self):
        """Returns the length of the source stream, determining it if not already known."""
        if self._stream_length is None:
            try:
                current_position = self.source_stream.tell()
                self.source_stream.seek(0, 2)
                self._stream_length = self.source_stream.tell()
                self.source_stream.seek(current_position, 0)
            except Exception as error:
                # Catch-all for unknown issues encountered trying to seek for stream length
                raise NotSupportedError(error)
        return self._stream_length

    @property
    def header(self):
        """Returns the message header, reading it if it is not already read.

        :returns: Parsed message header
        :rtype: aws_encryption_sdk.structures.MessageHeader
        """
        if not self._message_prepped:
            self._prep_message()
        return self._header

    def __enter__(self):
        """Handles entry to with block."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Handles closing of stream upon exist of with block."""
        try:
            self.close()
        except AWSEncryptionSDKClientError:
            # All known exceptions in close are safe to ignore.
            # Only raise unknown exceptions in close.
            _LOGGER.exception("Error on closing")
        return False

    def readable(self):
        # () -> bool
        """Return `True` if the stream can be read from.

        :rtype: bool
        """
        # Open streams are currently always readable.
        return not self.closed

    def read(self, b=-1):
        """Returns either the requested number of bytes or the entire stream.

        :param int b: Number of bytes to read
        :returns: Processed (encrypted or decrypted) bytes from source stream
        :rtype: bytes
        """
        # Any negative value for b is interpreted as a full read
        # None is also accepted for legacy compatibility
        if b is None or b < 0:
            b = -1

        _LOGGER.debug("Stream read called, requesting %d bytes", b)
        output = io.BytesIO()

        if not self._message_prepped:
            self._prep_message()

        if self.closed:
            raise ValueError("I/O operation on closed file")

        if b >= 0:
            self._read_bytes(b)
            output.write(self.output_buffer[:b])
            self.output_buffer = self.output_buffer[b:]
        else:
            while True:
                line = self.readline()
                if not line:
                    break
                output.write(line)

        self.bytes_read += output.tell()
        _LOGGER.debug("Returning %d bytes of %d bytes requested", output.tell(), b)
        return output.getvalue()

    def tell(self):
        """Returns the current position in the stream."""
        return self.bytes_read

    def writable(self):
        """Overwrites the parent writable method"""
        return False

    def writelines(self, lines):
        """Overwrites the parent writelines method"""
        raise NotImplementedError("writelines is not available for this object")

    def write(self, b):
        """Overwrites the parent write method"""
        raise NotImplementedError("write is not available for this object")

    def seek(self, offset, whence=0):
        """Overwrites the parent seek method"""
        raise NotImplementedError("seek is not available for this object")

    def readline(self):
        """Read a chunk of the output"""
        _LOGGER.info("reading line")
        line = self.read(self.line_length)
        if len(line) < self.line_length:
            _LOGGER.info("all lines read")
        return line

    def readlines(self):
        """Reads all chunks of output, outputting a list as defined in the IOBase specification."""
        return [line for line in self]

    def __iter__(self):
        """Make this class and subclasses identify as iterators."""
        return self

    def next(self):
        """Provides hook for Python2 iterator functionality."""
        _LOGGER.debug("reading next")
        if self.closed:
            _LOGGER.debug("stream is closed")
            raise StopIteration()

        line = self.readline()
        if not line:
            _LOGGER.debug("nothing more to read")
            raise StopIteration()

        return line

    #: Provides hook for Python3 iterator functionality.
    __next__ = next


@attr.s(hash=True)
class EncryptorConfig(_ClientConfig):
    """Configuration object for StreamEncryptor class.

    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param materials_manager: `CryptoMaterialsManager` from which to obtain cryptographic materials
        (either `materials_manager` or `key_provider` required)
    :type materials_manager: aws_encryption_sdk.materials_manager.base.CryptoMaterialsManager
    :param key_provider: `MasterKeyProvider` from which to obtain data keys for encryption
        (either `materials_manager` or `key_provider` required)
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and unframed message is being written or read() is called,
            will attempt to seek() to the end of the stream and tell() to find the length of source data.

        .. note::
            .. versionadded:: 1.3.0

            If `source_length` and `materials_manager` are both provided, the total plaintext bytes
            encrypted will not be allowed to exceed `source_length`. To maintain backwards compatibility,
            this is not enforced if a `key_provider` is provided.

    :param dict encryption_context: Dictionary defining encryption context
    :param algorithm: Algorithm to use for encryption (optional)
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param int frame_length: Frame length in bytes (optional)
    """

    encryption_context = attr.ib(
        hash=False,  # dictionaries are not hashable
        default=attr.Factory(dict),
        validator=attr.validators.instance_of(dict),
    )
    algorithm = attr.ib(
        hash=True, default=None, validator=attr.validators.optional(attr.validators.instance_of(Algorithm))
    )
    frame_length = attr.ib(hash=True, default=FRAME_LENGTH, validator=attr.validators.instance_of(six.integer_types))


class StreamEncryptor(_EncryptionStream):  # pylint: disable=too-many-instance-attributes
    """Provides a streaming encryptor for encrypting a stream source.
    Behaves as a standard file-like object.

    .. note::
        Take care when encrypting framed messages with large frame length and large non-framed
        messages.  See :class:`aws_encryption_sdk.stream` for more details.

    .. note::
        If config is provided, all other parameters are ignored.

    :param config: Client configuration object (config or individual parameters required)
    :type config: aws_encryption_sdk.streaming_client.EncryptorConfig
    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param materials_manager: `CryptoMaterialsManager` from which to obtain cryptographic materials
        (either `materials_manager` or `key_provider` required)
    :type materials_manager: aws_encryption_sdk.materials_manager.base.CryptoMaterialsManager
    :param key_provider: `MasterKeyProvider` from which to obtain data keys for encryption
        (either `materials_manager` or `key_provider` required)
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and unframed message is being written or read() is called,
            will attempt to seek() to the end of the stream and tell() to find the length of source data.

        .. note::
            .. versionadded:: 1.3.0

            If `source_length` and `materials_manager` are both provided, the total plaintext bytes
            encrypted will not be allowed to exceed `source_length`. To maintain backwards compatibility,
            this is not enforced if a `key_provider` is provided.

    :param dict encryption_context: Dictionary defining encryption context
    :param algorithm: Algorithm to use for encryption
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param int frame_length: Frame length in bytes
    """

    _config_class = EncryptorConfig

    def __init__(self, **kwargs):  # pylint: disable=unused-argument,super-init-not-called
        """Prepares necessary initial values."""
        self.sequence_number = 1

        self.content_type = aws_encryption_sdk.internal.utils.content_type(self.config.frame_length)
        self._bytes_encrypted = 0

        if self.config.frame_length == 0 and (
            self.config.source_length is not None and self.config.source_length > MAX_NON_FRAMED_SIZE
        ):
            raise SerializationError("Source too large for non-framed message")

        self.__unframed_plaintext_cache = io.BytesIO()
        self.__message_complete = False

    def ciphertext_length(self):
        """Returns the length of the resulting ciphertext message in bytes.

        :rtype: int
        """
        return aws_encryption_sdk.internal.formatting.ciphertext_length(
            header=self.header, plaintext_length=self.stream_length
        )

    def _prep_message(self):
        """Performs initial message setup.

        :raises MasterKeyProviderError: if primary master key is not a member of supplied MasterKeyProvider
        :raises MasterKeyProviderError: if no Master Keys are returned from key_provider
        """
        message_id = aws_encryption_sdk.internal.utils.message_id()

        try:
            plaintext_length = self.stream_length
        except NotSupportedError:
            plaintext_length = None
        encryption_materials_request = EncryptionMaterialsRequest(
            algorithm=self.config.algorithm,
            encryption_context=self.config.encryption_context.copy(),
            frame_length=self.config.frame_length,
            plaintext_rostream=aws_encryption_sdk.internal.utils.streams.ROStream(self.source_stream),
            plaintext_length=plaintext_length,
        )
        self._encryption_materials = self.config.materials_manager.get_encryption_materials(
            request=encryption_materials_request
        )

        if self.config.algorithm is not None and self._encryption_materials.algorithm != self.config.algorithm:
            raise ActionNotAllowedError(
                (
                    "Cryptographic materials manager provided algorithm suite"
                    " differs from algorithm suite in request.\n"
                    "Required: {requested}\n"
                    "Provided: {provided}"
                ).format(requested=self.config.algorithm, provided=self._encryption_materials.algorithm)
            )

        if self._encryption_materials.signing_key is None:
            self.signer = None
        else:
            self.signer = Signer.from_key_bytes(
                algorithm=self._encryption_materials.algorithm, key_bytes=self._encryption_materials.signing_key
            )
        aws_encryption_sdk.internal.utils.validate_frame_length(
            frame_length=self.config.frame_length, algorithm=self._encryption_materials.algorithm
        )

        self._derived_data_key = derive_data_encryption_key(
            source_key=self._encryption_materials.data_encryption_key.data_key,
            algorithm=self._encryption_materials.algorithm,
            message_id=message_id,
        )

        self._header = MessageHeader(
            version=VERSION,
            type=TYPE,
            algorithm=self._encryption_materials.algorithm,
            message_id=message_id,
            encryption_context=self._encryption_materials.encryption_context,
            encrypted_data_keys=self._encryption_materials.encrypted_data_keys,
            content_type=self.content_type,
            content_aad_length=0,
            header_iv_length=self._encryption_materials.algorithm.iv_len,
            frame_length=self.config.frame_length,
        )
        self._write_header()
        if self.content_type == ContentType.NO_FRAMING:
            self._prep_non_framed()
        self._message_prepped = True

    def _write_header(self):
        """Builds the message header and writes it to the output stream."""
        self.output_buffer += serialize_header(header=self._header, signer=self.signer)
        self.output_buffer += serialize_header_auth(
            algorithm=self._encryption_materials.algorithm,
            header=self.output_buffer,
            data_encryption_key=self._derived_data_key,
            signer=self.signer,
        )

    def _prep_non_framed(self):
        """Prepare the opening data for a non-framed message."""
        try:
            plaintext_length = self.stream_length
            self.__unframed_plaintext_cache = self.source_stream
        except NotSupportedError:
            # We need to know the plaintext length before we can start processing the data.
            # If we cannot seek on the source then we need to read the entire source into memory.
            self.__unframed_plaintext_cache = io.BytesIO()
            self.__unframed_plaintext_cache.write(self.source_stream.read())
            plaintext_length = self.__unframed_plaintext_cache.tell()
            self.__unframed_plaintext_cache.seek(0)

        aad_content_string = aws_encryption_sdk.internal.utils.get_aad_content_string(
            content_type=self.content_type, is_final_frame=True
        )
        associated_data = assemble_content_aad(
            message_id=self._header.message_id,
            aad_content_string=aad_content_string,
            seq_num=1,
            length=plaintext_length,
        )
        self.encryptor = Encryptor(
            algorithm=self._encryption_materials.algorithm,
            key=self._derived_data_key,
            associated_data=associated_data,
            iv=non_framed_body_iv(self._encryption_materials.algorithm),
        )
        self.output_buffer += serialize_non_framed_open(
            algorithm=self._encryption_materials.algorithm,
            iv=self.encryptor.iv,
            plaintext_length=plaintext_length,
            signer=self.signer,
        )

    def _read_bytes_to_non_framed_body(self, b):
        """Reads the requested number of bytes from source to a streaming non-framed message body.

        :param int b: Number of bytes to read
        :returns: Encrypted bytes from source stream
        :rtype: bytes
        """
        _LOGGER.debug("Reading %d bytes", b)
        plaintext = self.__unframed_plaintext_cache.read(b)
        plaintext_length = len(plaintext)
        if self.tell() + len(plaintext) > MAX_NON_FRAMED_SIZE:
            raise SerializationError("Source too large for non-framed message")

        ciphertext = self.encryptor.update(plaintext)
        self._bytes_encrypted += plaintext_length
        if self.signer is not None:
            self.signer.update(ciphertext)

        if len(plaintext) < b:
            _LOGGER.debug("Closing encryptor after receiving only %d bytes of %d bytes requested", plaintext_length, b)

            closing = self.encryptor.finalize()

            if self.signer is not None:
                self.signer.update(closing)

            closing += serialize_non_framed_close(tag=self.encryptor.tag, signer=self.signer)

            if self.signer is not None:
                closing += serialize_footer(self.signer)
            self.__message_complete = True
            return ciphertext + closing

        return ciphertext

    def _read_bytes_to_framed_body(self, b):
        """Reads the requested number of bytes from source to a streaming framed message body.

        :param int b: Number of bytes to read
        :returns: Bytes read from source stream, encrypted, and serialized
        :rtype: bytes
        """
        _LOGGER.debug("collecting %d bytes", b)
        _b = b

        if b > 0:
            _frames_to_read = math.ceil(b / float(self.config.frame_length))
            b = int(_frames_to_read * self.config.frame_length)
        _LOGGER.debug("%d bytes requested; reading %d bytes after normalizing to frame length", _b, b)

        plaintext = self.source_stream.read(b)
        plaintext_length = len(plaintext)
        _LOGGER.debug("%d bytes read from source", plaintext_length)

        finalize = False

        if b < 0 or plaintext_length < b:
            _LOGGER.debug("Final plaintext read from source")
            finalize = True

        output = b""
        final_frame_written = False

        while (
            # If not finalizing on this pass, exit when plaintext is exhausted
            (not finalize and plaintext)
            # If finalizing on this pass, wait until final frame is written
            or (finalize and not final_frame_written)
        ):
            current_plaintext_length = len(plaintext)
            is_final_frame = finalize and current_plaintext_length < self.config.frame_length
            bytes_in_frame = min(current_plaintext_length, self.config.frame_length)
            _LOGGER.debug(
                "Writing %d bytes into%s frame %d",
                bytes_in_frame,
                " final" if is_final_frame else "",
                self.sequence_number,
            )
            self._bytes_encrypted += bytes_in_frame
            ciphertext, plaintext = serialize_frame(
                algorithm=self._encryption_materials.algorithm,
                plaintext=plaintext,
                message_id=self._header.message_id,
                data_encryption_key=self._derived_data_key,
                frame_length=self.config.frame_length,
                sequence_number=self.sequence_number,
                is_final_frame=is_final_frame,
                signer=self.signer,
            )
            final_frame_written = is_final_frame
            output += ciphertext
            self.sequence_number += 1

        if finalize:
            _LOGGER.debug("Writing footer")
            if self.signer is not None:
                output += serialize_footer(self.signer)
            self.__message_complete = True
        return output

    def _read_bytes(self, b):
        """Reads the requested number of bytes from a streaming message body.

        :param int b: Number of bytes to read
        :raises NotSupportedError: if content type is not supported
        """
        _LOGGER.debug("%d bytes requested from stream with content type: %s", b, self.content_type)
        if 0 <= b <= len(self.output_buffer) or self.__message_complete:
            _LOGGER.debug("No need to read from source stream or source stream closed")
            return

        if self.content_type == ContentType.FRAMED_DATA:
            _LOGGER.debug("Reading to framed body")
            self.output_buffer += self._read_bytes_to_framed_body(b)
        elif self.content_type == ContentType.NO_FRAMING:
            _LOGGER.debug("Reading to non-framed body")
            self.output_buffer += self._read_bytes_to_non_framed_body(b)
        else:
            raise NotSupportedError("Unsupported content type")

        # To maintain backwards compatibility, only enforce this if a CMM is provided by the caller.
        if self.config.key_provider is None and self.config.source_length is not None:
            # Enforce that if the caller provided a source length value, the total bytes encrypted
            # must not exceed that value.
            if self._bytes_encrypted > self.config.source_length:
                raise CustomMaximumValueExceeded(
                    "Bytes encrypted has exceeded stated source length estimate:\n{actual:d} > {estimated:d}".format(
                        actual=self._bytes_encrypted, estimated=self.config.source_length
                    )
                )

    def close(self):
        """Closes out the stream."""
        _LOGGER.debug("Closing stream")
        super(StreamEncryptor, self).close()


@attr.s(hash=True)
class DecryptorConfig(_ClientConfig):
    """Configuration object for StreamDecryptor class.

    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param materials_manager: `CryptoMaterialsManager` from which to obtain cryptographic materials
        (either `materials_manager` or `key_provider` required)
    :type materials_manager: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager
    :param key_provider: `MasterKeyProvider` from which to obtain data keys for decryption
        (either `materials_manager` or `key_provider` required)
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and read() is called, will attempt to seek()
            to the end of the stream and tell() to find the length of source data.

    :param int max_body_length: Maximum frame size (or content length for non-framed messages)
        in bytes to read from ciphertext message.
    """

    max_body_length = attr.ib(
        hash=True, default=None, validator=attr.validators.optional(attr.validators.instance_of(six.integer_types))
    )


class StreamDecryptor(_EncryptionStream):  # pylint: disable=too-many-instance-attributes
    """Provides a streaming encryptor for encrypting a stream source.
    Behaves as a standard file-like object.

    .. note::
        Take care when decrypting framed messages with large frame length and large non-framed
        messages.  See :class:`aws_encryption_sdk.stream` for more details.

    .. note::
        If config is provided, all other parameters are ignored.

    :param config: Client configuration object (config or individual parameters required)
    :type config: aws_encryption_sdk.streaming_client.DecryptorConfig
    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param materials_manager: `CryptoMaterialsManager` from which to obtain cryptographic materials
        (either `materials_manager` or `key_provider` required)
    :type materials_manager: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager
    :param key_provider: `MasterKeyProvider` from which to obtain data keys for decryption
        (either `materials_manager` or `key_provider` required)
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and read() is called, will attempt to seek()
            to the end of the stream and tell() to find the length of source data.

    :param int max_body_length: Maximum frame size (or content length for non-framed messages)
        in bytes to read from ciphertext message.
    """

    _config_class = DecryptorConfig

    def __init__(self, **kwargs):  # pylint: disable=unused-argument,super-init-not-called
        """Prepares necessary initial values."""
        self.last_sequence_number = 0
        self.__unframed_bytes_read = 0

    def _prep_message(self):
        """Performs initial message setup."""
        self._header, self.header_auth = self._read_header()
        if self._header.content_type == ContentType.NO_FRAMING:
            self._prep_non_framed()
        self._message_prepped = True

    def _read_header(self):
        """Reads the message header from the input stream.

        :returns: tuple containing deserialized header and header_auth objects
        :rtype: tuple of aws_encryption_sdk.structures.MessageHeader
            and aws_encryption_sdk.internal.structures.MessageHeaderAuthentication
        :raises CustomMaximumValueExceeded: if frame length is greater than the custom max value
        """
        header, raw_header = deserialize_header(self.source_stream)
        self.__unframed_bytes_read += len(raw_header)

        if (
            self.config.max_body_length is not None
            and header.content_type == ContentType.FRAMED_DATA
            and header.frame_length > self.config.max_body_length
        ):
            raise CustomMaximumValueExceeded(
                "Frame Size in header found larger than custom value: {found:d} > {custom:d}".format(
                    found=header.frame_length, custom=self.config.max_body_length
                )
            )

        decrypt_materials_request = DecryptionMaterialsRequest(
            encrypted_data_keys=header.encrypted_data_keys,
            algorithm=header.algorithm,
            encryption_context=header.encryption_context,
        )
        decryption_materials = self.config.materials_manager.decrypt_materials(request=decrypt_materials_request)
        if decryption_materials.verification_key is None:
            self.verifier = None
        else:
            self.verifier = Verifier.from_key_bytes(
                algorithm=header.algorithm, key_bytes=decryption_materials.verification_key
            )
        if self.verifier is not None:
            self.verifier.update(raw_header)

        header_auth = deserialize_header_auth(
            stream=self.source_stream, algorithm=header.algorithm, verifier=self.verifier
        )
        self._derived_data_key = derive_data_encryption_key(
            source_key=decryption_materials.data_key.data_key, algorithm=header.algorithm, message_id=header.message_id
        )
        validate_header(header=header, header_auth=header_auth, raw_header=raw_header, data_key=self._derived_data_key)
        return header, header_auth

    def _prep_non_framed(self):
        """Prepare the opening data for a non-framed message."""
        self._unframed_body_iv, self.body_length = deserialize_non_framed_values(
            stream=self.source_stream, header=self._header, verifier=self.verifier
        )

        if self.config.max_body_length is not None and self.body_length > self.config.max_body_length:
            raise CustomMaximumValueExceeded(
                "Non-framed message content length found larger than custom value: {found:d} > {custom:d}".format(
                    found=self.body_length, custom=self.config.max_body_length
                )
            )

        self.__unframed_bytes_read += self._header.algorithm.iv_len
        self.__unframed_bytes_read += 8  # encrypted content length field
        self._body_start = self.__unframed_bytes_read
        self._body_end = self._body_start + self.body_length

    def _read_bytes_from_non_framed_body(self, b):
        """Reads the requested number of bytes from a streaming non-framed message body.

        :param int b: Number of bytes to read
        :returns: Decrypted bytes from source stream
        :rtype: bytes
        """
        _LOGGER.debug("starting non-framed body read")
        # Always read the entire message for non-framed message bodies.
        bytes_to_read = self.body_length

        _LOGGER.debug("%d bytes requested; reading %d bytes", b, bytes_to_read)
        ciphertext = self.source_stream.read(bytes_to_read)

        if len(self.output_buffer) + len(ciphertext) < self.body_length:
            raise SerializationError("Total message body contents less than specified in body description")

        if self.verifier is not None:
            self.verifier.update(ciphertext)

        tag = deserialize_tag(stream=self.source_stream, header=self._header, verifier=self.verifier)

        aad_content_string = aws_encryption_sdk.internal.utils.get_aad_content_string(
            content_type=self._header.content_type, is_final_frame=True
        )
        associated_data = assemble_content_aad(
            message_id=self._header.message_id,
            aad_content_string=aad_content_string,
            seq_num=1,
            length=self.body_length,
        )
        self.decryptor = Decryptor(
            algorithm=self._header.algorithm,
            key=self._derived_data_key,
            associated_data=associated_data,
            iv=self._unframed_body_iv,
            tag=tag,
        )

        plaintext = self.decryptor.update(ciphertext)
        plaintext += self.decryptor.finalize()

        self.footer = deserialize_footer(stream=self.source_stream, verifier=self.verifier)
        return plaintext

    def _read_bytes_from_framed_body(self, b):
        """Reads the requested number of bytes from a streaming framed message body.

        :param int b: Number of bytes to read
        :returns: Bytes read from source stream and decrypted
        :rtype: bytes
        """
        plaintext = b""
        final_frame = False
        _LOGGER.debug("collecting %d bytes", b)
        while len(plaintext) < b and not final_frame:
            _LOGGER.debug("Reading frame")
            frame_data, final_frame = deserialize_frame(
                stream=self.source_stream, header=self._header, verifier=self.verifier
            )
            _LOGGER.debug("Read complete for frame %d", frame_data.sequence_number)
            if frame_data.sequence_number != self.last_sequence_number + 1:
                raise SerializationError("Malformed message: frames out of order")
            self.last_sequence_number += 1
            aad_content_string = aws_encryption_sdk.internal.utils.get_aad_content_string(
                content_type=self._header.content_type, is_final_frame=frame_data.final_frame
            )
            associated_data = assemble_content_aad(
                message_id=self._header.message_id,
                aad_content_string=aad_content_string,
                seq_num=frame_data.sequence_number,
                length=len(frame_data.ciphertext),
            )
            plaintext += decrypt(
                algorithm=self._header.algorithm,
                key=self._derived_data_key,
                encrypted_data=frame_data,
                associated_data=associated_data,
            )
            plaintext_length = len(plaintext)
            _LOGGER.debug("bytes collected: %d", plaintext_length)
        if final_frame:
            _LOGGER.debug("Reading footer")
            self.footer = deserialize_footer(stream=self.source_stream, verifier=self.verifier)

        return plaintext

    def _read_bytes(self, b):
        """Reads the requested number of bytes from a streaming message body.

        :param int b: Number of bytes to read
        :raises NotSupportedError: if content type is not supported
        """
        if hasattr(self, "footer"):
            _LOGGER.debug("Source stream processing complete")
            return

        buffer_length = len(self.output_buffer)
        if 0 <= b <= buffer_length:
            _LOGGER.debug("%d bytes requested less than or equal to current output buffer size %d", b, buffer_length)
            return

        if self._header.content_type == ContentType.FRAMED_DATA:
            self.output_buffer += self._read_bytes_from_framed_body(b)
        elif self._header.content_type == ContentType.NO_FRAMING:
            self.output_buffer += self._read_bytes_from_non_framed_body(b)
        else:
            raise NotSupportedError("Unsupported content type")

    def close(self):
        """Closes out the stream."""
        _LOGGER.debug("Closing stream")
        if not hasattr(self, "footer"):
            raise SerializationError("Footer not read")
        super(StreamDecryptor, self).close()


__all__ = ("DecryptorConfig", "EncryptorConfig", "StreamDecryptor", "StreamEncryptor")
