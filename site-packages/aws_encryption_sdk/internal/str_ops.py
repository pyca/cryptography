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
"""Helper functions for consistently obtaining str and bytes objects in both Python2 and Python3."""
import codecs

import six

import aws_encryption_sdk.internal.defaults


def to_str(data):
    """Takes an input str or bytes object and returns an equivalent str object.

    :param data: Input data
    :type data: str or bytes
    :returns: Data normalized to str
    :rtype: str
    """
    if isinstance(data, bytes):
        return codecs.decode(data, aws_encryption_sdk.internal.defaults.ENCODING)
    return data


def to_bytes(data):
    """Takes an input str or bytes object and returns an equivalent bytes object.

    :param data: Input data
    :type data: str or bytes
    :returns: Data normalized to bytes
    :rtype: bytes
    """
    if isinstance(data, six.string_types) and not isinstance(data, bytes):
        return codecs.encode(data, aws_encryption_sdk.internal.defaults.ENCODING)
    return data
