# Copyright 2015 Donald Stufft
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import absolute_import, division, print_function

import sys

from .clean import clean

if sys.version_info >= (3,):
    from html import escape as html_escape
else:
    from cgi import escape

    def html_escape(s):
        return escape(s, quote=True).replace("'", '&#x27;')


def render(raw, **kwargs):
    rendered = html_escape(raw).replace("\n", "<br>")
    return clean(rendered, tags=["br"])
