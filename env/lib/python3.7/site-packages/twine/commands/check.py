# Copyright 2018 Dustin Ingram
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
from __future__ import unicode_literals

import argparse
import cgi
import re
import sys

try:
    from StringIO import StringIO
except ImportError:
    from _io import StringIO

import readme_renderer.markdown
import readme_renderer.rst
import readme_renderer.txt

from twine.commands import _find_dists
from twine.package import PackageFile

_RENDERERS = {
    None: readme_renderer.rst,  # Default if description_content_type is None
    "": readme_renderer.rst,  # Default if description_content_type is None
    "text/plain": readme_renderer.txt,
    "text/x-rst": readme_renderer.rst,
    "text/markdown": readme_renderer.markdown,
}


# Regular expression used to capture and reformat doctuils warnings into
# something that a human can understand. This is loosely borrowed from
# Sphinx: https://github.com/sphinx-doc/sphinx/blob
# /c35eb6fade7a3b4a6de4183d1dd4196f04a5edaf/sphinx/util/docutils.py#L199
_REPORT_RE = re.compile(
    r"^<string>:(?P<line>(?:\d+)?): "
    r"\((?P<level>DEBUG|INFO|WARNING|ERROR|SEVERE)/(\d+)?\) "
    r"(?P<message>.*)",
    re.DOTALL | re.MULTILINE,
)


class _WarningStream(object):
    def __init__(self):
        self.output = StringIO()

    def write(self, text):
        matched = _REPORT_RE.search(text)

        if not matched:
            self.output.write(text)
            return

        self.output.write(
            "line {line}: {level_text}: {message}\n".format(
                level_text=matched.group("level").capitalize(),
                line=matched.group("line"),
                message=matched.group("message").rstrip("\r\n"),
            )
        )

    def __str__(self):
        return self.output.getvalue()


def check(dists, output_stream=sys.stdout):
    uploads = [i for i in _find_dists(dists) if not i.endswith(".asc")]
    stream = _WarningStream()
    failure = False

    for filename in uploads:
        output_stream.write("Checking distribution %s: " % filename)
        package = PackageFile.from_filename(filename, comment=None)

        metadata = package.metadata_dictionary()
        content_type, parameters = cgi.parse_header(
            metadata.get("description_content_type") or ""
        )

        # Get the appropriate renderer
        renderer = _RENDERERS.get(content_type, readme_renderer.txt)

        # Actually render the given value
        rendered = renderer.render(
            metadata.get("description"), stream=stream, **parameters
        )

        if rendered is None:
            failure = True
            output_stream.write("Failed\n")
            output_stream.write(
                "The project's long_description has invalid markup which will "
                "not be rendered on PyPI. The following syntax errors were "
                "detected:\n%s" % stream
            )
        else:
            output_stream.write("Passed\n")

    return failure


def main(args):
    parser = argparse.ArgumentParser(prog="twine check")
    parser.add_argument(
        "dists",
        nargs="+",
        metavar="dist",
        help="The distribution files to check, usually dist/*",
    )

    args = parser.parse_args(args)

    # Call the check function with the arguments from the command line
    return check(args.dists)
