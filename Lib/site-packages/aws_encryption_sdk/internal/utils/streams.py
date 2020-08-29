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
"""Helper stream utility objects for AWS Encryption SDK."""
import io

from wrapt import ObjectProxy

from aws_encryption_sdk.exceptions import ActionNotAllowedError
from aws_encryption_sdk.internal.str_ops import to_bytes


class ROStream(ObjectProxy):
    """Provides a read-only interface on top of a file-like object.

    Used to provide MasterKeyProviders with read-only access to plaintext.

    :param wrapped: File-like object
    """

    def write(self, b):  # pylint: disable=unused-argument
        """Blocks calls to write.

        :raises ActionNotAllowedError: when called
        """
        raise ActionNotAllowedError("Write not allowed on ROStream objects")


class TeeStream(ObjectProxy):
    """Provides a ``tee``-like interface on top of a file-like object, which collects read bytes
    into a local :class:`io.BytesIO`.

    :param wrapped: File-like object
    :param tee: Stream to copy read bytes into.
    :type tee: io.BaseIO
    """

    __tee = None  # Prime ObjectProxy's attributes to allow setting in init.

    def __init__(self, wrapped, tee):
        """Creates the local tee stream."""
        super(TeeStream, self).__init__(wrapped)
        self.__tee = tee

    def read(self, b=None):
        """Reads data from source, copying it into ``tee`` before returning.

        :param int b: number of bytes to read
        """
        data = self.__wrapped__.read(b)
        self.__tee.write(data)
        return data


class InsistentReaderBytesIO(ObjectProxy):
    """Wrapper around a readable stream that insists on reading exactly the requested
    number of bytes. It will keep trying to read bytes from the wrapped stream until
    either the requested number of bytes are available or the wrapped stream has
    nothing more to return.

    :param wrapped: File-like object
    """

    def read(self, b=-1):
        """Keep reading from source stream until either the source stream is done
        or the requested number of bytes have been obtained.

        :param int b: number of bytes to read
        :return: All bytes read from wrapped stream
        :rtype: bytes
        """
        remaining_bytes = b
        data = io.BytesIO()
        while True:
            try:
                chunk = to_bytes(self.__wrapped__.read(remaining_bytes))
            except ValueError:
                if self.__wrapped__.closed:
                    break
                raise

            if not chunk:
                break

            data.write(chunk)
            remaining_bytes -= len(chunk)

            if remaining_bytes <= 0:
                break
        return data.getvalue()
