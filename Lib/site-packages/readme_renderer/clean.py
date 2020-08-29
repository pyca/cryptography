# Copyright 2014 Donald Stufft
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

import functools

import bleach
import bleach.callbacks
import bleach.linkifier
import bleach.sanitizer


ALLOWED_TAGS = [
    # Bleach Defaults
    "a", "abbr", "acronym", "b", "blockquote", "code", "em", "i", "li", "ol",
    "strong", "ul",

    # Custom Additions
    "br", "caption", "cite", "col", "colgroup", "dd", "del", "details", "div",
    "dl", "dt", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "img", "p", "pre",
    "span", "sub", "summary", "sup", "table", "tbody", "td", "th", "thead",
    "tr", "tt", "kbd", "var",
]

ALLOWED_ATTRIBUTES = {
    # Bleach Defaults
    "a": ["href", "title"],
    "abbr": ["title"],
    "acronym": ["title"],

    # Custom Additions
    "*": ["id"],
    "hr": ["class"],
    "img": ["src", "width", "height", "alt", "align", "class"],
    "span": ["class"],
    "th": ["align"],
    "td": ["align"],
    "code": ["class"],
    "p": ["align"],
}

ALLOWED_STYLES = [
]


def clean(html, tags=None, attributes=None, styles=None):
    if tags is None:
        tags = ALLOWED_TAGS
    if attributes is None:
        attributes = ALLOWED_ATTRIBUTES
    if styles is None:
        styles = ALLOWED_STYLES

    # Clean the output using Bleach
    cleaner = bleach.sanitizer.Cleaner(
        tags=tags,
        attributes=attributes,
        styles=styles,
        filters=[
            # Bleach Linkify makes it easy to modify links, however, we will
            # not be using it to create additional links.
            functools.partial(
                bleach.linkifier.LinkifyFilter,
                callbacks=[
                    lambda attrs, new: attrs if not new else None,
                    bleach.callbacks.nofollow,
                ],
                skip_tags=["pre"],
                parse_email=False,
            ),
        ],
    )
    try:
        cleaned = cleaner.clean(html)
        return cleaned
    except ValueError:
        return None
