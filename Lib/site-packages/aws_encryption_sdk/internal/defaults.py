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
"""Default values for AWS Encryption SDK."""
import io

import aws_encryption_sdk.identifiers

#: Default chunk size to read data from sources in streaming clients
LINE_LENGTH = io.DEFAULT_BUFFER_SIZE

#: Standard string encoding where needed
ENCODING = "utf-8"
#: Default frame length when using framing
FRAME_LENGTH = 4096
#: Message ID length as defined in specification
MESSAGE_ID_LENGTH = 16
#: Current specification version
VERSION = aws_encryption_sdk.identifiers.SerializationVersion.V1
#: Default message structure Type as defined in specification
TYPE = aws_encryption_sdk.identifiers.ObjectType.CUSTOMER_AE_DATA
#: Default algorithm as defined in specification
ALGORITHM = aws_encryption_sdk.identifiers.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384

#: Key to add encoded signing key to encryption context dictionary as defined in specification
ENCODED_SIGNER_KEY = "aws-crypto-public-key"

#: Maximum number of messages which are allowed to be encrypted under a single cached data key
MAX_MESSAGES_PER_KEY = 4294967296  # 2 ** 32
#: Maximum number of bytes which are allowed to be encrypted under a single cached data key
MAX_BYTES_PER_KEY = 9223372036854775807  # 2 ** 63 - 1
#: Maximum number of frames allowed in one message as defined in specification
MAX_FRAME_COUNT = 4294967295  # 2 ** 32 - 1
#: Maximum bytes allowed in a single frame as defined in specification
MAX_FRAME_SIZE = 2147483647  # 2 ** 31 - 1
#: Maximum bytes allowed in a non-framed message ciphertext as defined in specification
MAX_GCM_CONTENT_SIZE = MAX_NON_FRAMED_SIZE = 68719476704  # 2 ** 36 - 32

#: Maximum number of AAD bytes allowed as defined in specification
MAX_BYTE_ARRAY_SIZE = 65535  # 2 ** 16 - 1
