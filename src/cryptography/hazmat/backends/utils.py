# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function


class _SizeValidator(object):
    def __init__(self, max_bytes, label):
        self._max_bytes = int(max_bytes)
        self._len = 0
        self._label = label

    def update(self, data):
        self._len += len(data)

    def validate(self):
        if self._len > self._max_bytes:
            raise ValueError("Exceeded %s byte limit." % self._label)

    def update_and_validate(self, data):
        self.update(data)
        self.validate()
