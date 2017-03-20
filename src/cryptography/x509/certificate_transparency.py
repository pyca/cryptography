# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function


class SignedCertificateTimestamp(object):
    def __init__(self, version, log_id, timestamp, entry_type):
        # TODO: extensions, signature value, NID.
        self._version = version
        self._log_id = log_id
        self._timestamp = timestamp
        self._entry_type = entry_type
