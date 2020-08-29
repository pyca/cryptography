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
"""
Helper functions used for generating deterministic initialization vectors (IVs).

Deterministic IVs are used to reduce the probability of IV/message-key pair collisions when caching
data keys.

Prior to introducing caching, a statement could safely be made that every encrypt call resulted in a new
data key which would only be used with a single message. With the introduction of caching, this statement
by definition becomes false.

This is a problem because there are cryptographic limits on the number of times AES can be safely invoked
using the same key (or using keys derived from the same key) and a random IV. In framed messages, this
manifests as the total number of frames which can be safely encrypted under the same data key across all
messages for which the data key is reused.

By using a random IV for each frame, we actually decrease the number of frames which can be safely encrypted
under the same data key.  Rather than attempting to track the number of frames across messages, we decided
to move to a deterministic IV constructed in such a way that it is guaranteed to never conflict within the
same message.  This means that we can consider only the likelihood of KDF collisions, which raises the limit
sufficiently that we can assume that every message contains the maximum 2^32 invocations (2^32 - 1 frames +
header auth).

Each IV is constructed from two big-endian byte arrays concatenated in the following order:

1. **64 bytes** : 0 (reserved space for possible future use)
2. **32 bytes** : frame sequence number (0 for the header auth calculation)
"""
import struct

from aws_encryption_sdk.exceptions import ActionNotAllowedError
from aws_encryption_sdk.internal.defaults import MAX_FRAME_COUNT


def frame_iv(algorithm, sequence_number):
    """Builds the deterministic IV for a body frame.

    :param algorithm: Algorithm for which to build IV
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param int sequence_number: Frame sequence number
    :returns: Generated IV
    :rtype: bytes
    :raises ActionNotAllowedError: if sequence number of out bounds
    """
    if sequence_number < 1 or sequence_number > MAX_FRAME_COUNT:
        raise ActionNotAllowedError(
            "Invalid frame sequence number: {actual}\nMust be between 1 and {max}".format(
                actual=sequence_number, max=MAX_FRAME_COUNT
            )
        )
    prefix_len = algorithm.iv_len - 4
    prefix = b"\x00" * prefix_len
    return prefix + struct.pack(">I", sequence_number)


def non_framed_body_iv(algorithm):
    """Builds the deterministic IV for a non-framed body.

    :param algorithm: Algorithm for which to build IV
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :returns: Generated IV
    :rtype: bytes
    """
    return frame_iv(algorithm, 1)


def header_auth_iv(algorithm):
    """Builds the deterministic IV for header authentication.

    :param algorithm: Algorithm for which to build IV
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :returns: Generated IV
    :rtype: bytes
    """
    return b"\x00" * algorithm.iv_len
