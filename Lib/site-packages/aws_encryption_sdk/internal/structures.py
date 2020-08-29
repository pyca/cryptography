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
"""Public data structures for aws_encryption_sdk."""
import attr
import six


@attr.s(hash=True)
class EncryptedData(object):
    """Holds encrypted data.

    :param bytes iv: Initialization Vector
    :param bytes ciphertext: Ciphertext
    :param bytes tag: Encryption tag
    """

    iv = attr.ib(hash=True, validator=attr.validators.optional(attr.validators.instance_of(bytes)))
    ciphertext = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    tag = attr.ib(hash=True, validator=attr.validators.optional(attr.validators.instance_of(bytes)))


@attr.s(hash=True)
class MessageHeaderAuthentication(object):
    """Deserialized message header authentication

    :param bytes iv: Initialization Vector
    :param bytes tag: Encryption Tag
    """

    iv = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    tag = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))


@attr.s(hash=True)
class MessageFrameBody(object):
    """Deserialized message frame

    :param bytes iv: Initialization Vector
    :param bytes ciphertext: Ciphertext
    :param bytes tag: Encryption Tag
    :param int sequence_number: Frame sequence number
    :param bool final_frame: Identifies final frames
    """

    iv = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    ciphertext = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    tag = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    sequence_number = attr.ib(hash=True, validator=attr.validators.instance_of(six.integer_types))
    final_frame = attr.ib(hash=True, validator=attr.validators.instance_of(bool))


@attr.s(hash=True)
class MessageNoFrameBody(object):
    """Deserialized message body with no framing

    :param bytes iv: Initialization Vector
    :param bytes ciphertext: Ciphertext
    :param bytes tag: Encryption Tag
    """

    iv = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    ciphertext = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    tag = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    sequence_number = 1
    final_frame = True  # Never used, but set here to provide a consistent API with MessageFrameBody


@attr.s(hash=True)
class MessageFooter(object):
    """Deserialized message footer

    :param bytes signature: Message signature
    """

    signature = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
