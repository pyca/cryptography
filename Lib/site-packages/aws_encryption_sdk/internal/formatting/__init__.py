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
"""Formatting functions for aws_encryption_sdk."""
from .serialize import serialize_header


def header_length(header):
    """Calculates the ciphertext message header length, given a complete header.

    :param header: Complete message header object
    :type header: aws_encryption_sdk.structures.MessageHeader
    :rtype: int
    """
    # Because encrypted data key lengths may not be knowable until the ciphertext
    #  is received from the providers, just serialize the header directly.
    header_length = len(serialize_header(header))
    header_length += header.algorithm.iv_len  # Header Authentication IV
    header_length += header.algorithm.auth_len  # Header Authentication Tag
    return header_length


def _non_framed_body_length(header, plaintext_length):
    """Calculates the length of a non-framed message body, given a complete header.

    :param header: Complete message header object
    :type header: aws_encryption_sdk.structures.MessageHeader
    :param int plaintext_length: Length of plaintext in bytes
    :rtype: int
    """
    body_length = header.algorithm.iv_len  # IV
    body_length += 8  # Encrypted Content Length
    body_length += plaintext_length  # Encrypted Content
    body_length += header.algorithm.auth_len  # Authentication Tag
    return body_length


def _standard_frame_length(header):
    """Calculates the length of a standard ciphertext frame, given a complete header.

    :param header: Complete message header object
    :type header: aws_encryption_sdk.structures.MessageHeader
    :rtype: int
    """
    frame_length = 4  # Sequence Number
    frame_length += header.algorithm.iv_len  # IV
    frame_length += header.frame_length  # Encrypted Content
    frame_length += header.algorithm.auth_len  # Authentication Tag
    return frame_length


def _final_frame_length(header, final_frame_bytes):
    """Calculates the length of a final ciphertext frame, given a complete header
    and the number of bytes of ciphertext in the final frame.

    :param header: Complete message header object
    :type header: aws_encryption_sdk.structures.MessageHeader
    :param int final_frame_bytes: Bytes of ciphertext in the final frame
    :rtype: int
    """
    final_frame_length = 4  # Sequence Number End
    final_frame_length += 4  # Sequence Number
    final_frame_length += header.algorithm.iv_len  # IV
    final_frame_length += 4  # Encrypted Content Length
    final_frame_length += final_frame_bytes  # Encrypted Content
    final_frame_length += header.algorithm.auth_len  # Authentication Tag
    return final_frame_length


def body_length(header, plaintext_length):
    """Calculates the ciphertext message body length, given a complete header.

    :param header: Complete message header object
    :type header: aws_encryption_sdk.structures.MessageHeader
    :param int plaintext_length: Length of plaintext in bytes
    :rtype: int
    """
    body_length = 0
    if header.frame_length == 0:  # Non-framed
        body_length += _non_framed_body_length(header, plaintext_length)
    else:  # Framed
        frames, final_frame_bytes = divmod(plaintext_length, header.frame_length)
        body_length += frames * _standard_frame_length(header)
        body_length += _final_frame_length(header, final_frame_bytes)  # Final frame is always written
    return body_length


def footer_length(header):
    """Calculates the ciphertext message footer length, given a complete header.

    :param header: Complete message header object
    :type header: aws_encryption_sdk.structures.MessageHeader
    :rtype: int
    """
    footer_length = 0
    if header.algorithm.signing_algorithm_info is not None:
        footer_length += 2  # Signature Length
        footer_length += header.algorithm.signature_len  # Signature
    return footer_length


def ciphertext_length(header, plaintext_length):
    """Calculates the complete ciphertext message length, given a complete header.

    :param header: Complete message header object
    :type header: aws_encryption_sdk.structures.MessageHeader
    :param int plaintext_length: Length of plaintext in bytes
    :rtype: int
    """
    ciphertext_length = header_length(header)
    ciphertext_length += body_length(header, plaintext_length)
    ciphertext_length += footer_length(header)
    return ciphertext_length
