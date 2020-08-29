#!/usr/bin/env python3
# Copyright 2013 Donald Stufft
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
import http
import sys
from typing import Any

import colorama
import requests

from twine import cli
from twine import exceptions


def main() -> Any:
    try:
        result = cli.dispatch(sys.argv[1:])
    except requests.HTTPError as exc:
        status_code = exc.response.status_code
        status_phrase = http.HTTPStatus(status_code).phrase
        result = (
            f"{exc.__class__.__name__}: {status_code} {status_phrase} "
            f"from {exc.response.url}\n"
            f"{exc.response.reason}"
        )
    except exceptions.TwineException as exc:
        result = f"{exc.__class__.__name__}: {exc.args[0]}"

    return _format_error(result) if isinstance(result, str) else result


def _format_error(message: str) -> str:
    pre_style, post_style = "", ""
    if not cli.args.no_color:
        colorama.init()
        pre_style, post_style = colorama.Fore.RED, colorama.Style.RESET_ALL

    return f"{pre_style}{message}{post_style}"


if __name__ == "__main__":
    sys.exit(main())
