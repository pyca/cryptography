# Copyright 2015 Ian Cordasco
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
import os.path
from typing import List
from typing import cast

from twine import exceptions
from twine import package as package_file
from twine import settings


def register(register_settings: settings.Settings, package: str) -> None:
    repository_url = cast(str, register_settings.repository_config["repository"])
    print(f"Registering package to {repository_url}")
    repository = register_settings.create_repository()

    if not os.path.exists(package):
        raise exceptions.PackageNotFound(
            f'"{package}" does not exist on the file system.'
        )

    resp = repository.register(
        package_file.PackageFile.from_filename(package, register_settings.comment)
    )
    repository.close()

    if resp.is_redirect:
        raise exceptions.RedirectDetected.from_args(
            repository_url, resp.headers["location"],
        )

    resp.raise_for_status()


def main(args: List[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="twine register",
        description="register operation is not required with PyPI.org",
    )
    settings.Settings.register_argparse_arguments(parser)
    parser.add_argument(
        "package",
        metavar="package",
        help="File from which we read the package metadata.",
    )

    parsed_args = parser.parse_args(args)
    register_settings = settings.Settings.from_argparse(parsed_args)

    # Call the register function with the args from the command line
    register(register_settings, parsed_args.package)
