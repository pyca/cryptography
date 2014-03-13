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

import sys

import pretend

from cryptography.hazmat.bindings import utils


def test_create_modulename():
    pretend_ffi = pretend.stub(_cdefsources=["cdef sources go here"])
    source = "source code"
    name = utils._create_modulename(pretend_ffi, source, sys.version,
                                    sys.version_info)
    assert name == "_cffi_bcba7f4bx4a14b588"
