# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function


class _Reasons(object):
    BACKEND_MISSING_INTERFACE = object()
    UNSUPPORTED_HASH = object()
    UNSUPPORTED_CIPHER = object()
    UNSUPPORTED_PADDING = object()
    UNSUPPORTED_MGF = object()
    UNSUPPORTED_PUBLIC_KEY_ALGORITHM = object()
    UNSUPPORTED_ELLIPTIC_CURVE = object()


class UnsupportedAlgorithm(Exception):
    def __init__(self, message, reason=None):
        super(UnsupportedAlgorithm, self).__init__(message)
        self._reason = reason


class AlreadyFinalized(Exception):
    pass


class AlreadyUpdated(Exception):
    pass


class NotYetFinalized(Exception):
    pass


class InvalidTag(Exception):
    pass


class InvalidSignature(Exception):
    pass


class InternalError(Exception):
    pass


class InvalidKey(Exception):
    pass


class InvalidToken(Exception):
    pass
