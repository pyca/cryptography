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

import pretend

import pytest

from .skip_check import skip_check


class FakeInterface(object):
    pass


def test_skip_check():
    item = pretend.stub(keywords=["fake_name"], funcargs={"backend": True})
    with pytest.raises(pytest.skip.Exception) as exc_info:
        skip_check("fake_name", FakeInterface, item)
    assert exc_info.value.args[0] == "Backend does not support fake_name"
