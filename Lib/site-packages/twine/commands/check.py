# Copyright 2018 Dustin Ingram
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import cgi
import io
import re
import sys
import textwrap
from typing import IO
from typing import List
from typing import Optional
from typing import Tuple
from typing import cast

import readme_renderer.rst

from twine import commands
from twine import package as package_file

_RENDERERS = {
    None: readme_renderer.rst,  # Default if description_content_type is None
    "text/plain": None,  # Rendering cannot fail
    "text/x-rst": readme_renderer.rst,
    "text/markdown": None,  # Rendering cannot fail
}


# Regular expression used to capture and reformat docutils warnings into
# something that a human can understand. This is loosely borrowed from
# Sphinx: https://github.com/sphinx-doc/sphinx/blob
# /c35eb6fade7a3b4a6de4183d1dd4196f04a5edaf/sphinx/util/docutils.py#L199
_REPORT_RE = re.compile(
    r"^<string>:(?P<line>(?:\d+)?): "
    r"\((?P<level>DEBUG|INFO|WARNING|ERROR|SEVERE)/(\d+)?\) "
    r"(?P<message>.*)",
    re.DOTALL | re.MULTILINE,
)


class _WarningStream:
    def __init__(self) -> None:
        self.output = io.StringIO()

    def write(self, text: str) -> None:
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

    def __str__(self) -> str:
        return self.output.getvalue()


def _check_file(
    filename: str, render_warning_stream: _WarningStream
) -> Tuple[List[str], bool]:
    """Check given distribution."""
    warnings = []
    is_ok = True

    package = package_file.PackageFile.from_filename(filename, comment=None)

    metadata = package.metadata_dictionary()
    description = cast(Optional[str], metadata["description"])
    description_content_type = cast(Optional[str], metadata["description_content_type"])

    if description_content_type is None:
        warnings.append(
            "`long_description_content_type` missing. defaulting to `text/x-rst`."
        )
        description_content_type = "text/x-rst"

    content_type, params = cgi.parse_header(description_content_type)
    renderer = _RENDERERS.get(content_type, _RENDERERS[None])

    if description in {None, "UNKNOWN\n\n\n"}:
        warnings.append("`long_description` missing.")
    elif renderer:
        rendering_result = renderer.render(
            description, stream=render_warning_stream, **params
        )
        if rendering_result is None:
            is_ok = False

    return warnings, is_ok


def check(dists: List[str], output_stream: IO[str] = sys.stdout) -> bool:
    uploads = [i for i in commands._find_dists(dists) if not i.endswith(".asc")]
    if not uploads:  # Return early, if there are no files to check.
        output_stream.write("No files to check.\n")
        return False

    failure = False

    for filename in uploads:
        output_stream.write("Checking %s: " % filename)
        render_warning_stream = _WarningStream()
        warnings, is_ok = _check_file(filename, render_warning_stream)

        # Print the status and/or error
        if not is_ok:
            failure = True
            output_stream.write("FAILED\n")

            error_text = (
                "`long_description` has syntax errors in markup and "
                "would not be rendered on PyPI.\n"
            )
            output_stream.write(textwrap.indent(error_text, "  "))
            output_stream.write(textwrap.indent(str(render_warning_stream), "    "))
        elif warnings:
            output_stream.write("PASSED, with warnings\n")
        else:
            output_stream.write("PASSED\n")

        # Print warnings after the status and/or error
        for message in warnings:
            output_stream.write("  warning: " + message + "\n")

    return failure


def main(args: List[str]) -> bool:
    parser = argparse.ArgumentParser(prog="twine check")
    parser.add_argument(
        "dists",
        nargs="+",
        metavar="dist",
        help="The distribution files to check, usually dist/*",
    )

    parsed_args = parser.parse_args(args)

    # Call the check function with the arguments from the command line
    return check(parsed_args.dists)
