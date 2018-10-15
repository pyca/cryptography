# Copyright 2015 Ian Cordasco
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
from __future__ import absolute_import, unicode_literals, print_function

import argparse
import os.path

from twine.package import PackageFile
from twine import exceptions
from twine import settings


def register(register_settings, package):
    repository_url = register_settings.repository_config['repository']

    print("Registering package to {0}".format(repository_url))
    repository = register_settings.create_repository()

    if not os.path.exists(package):
        raise exceptions.PackageNotFound(
            '"{0}" does not exist on the file system.'.format(package)
        )

    resp = repository.register(
        PackageFile.from_filename(package, register_settings.comment)
    )
    repository.close()

    if resp.is_redirect:
        raise exceptions.RedirectDetected(
            ('"{0}" attempted to redirect to "{1}" during registration.'
             ' Aborting...').format(repository_url,
                                    resp.headers["location"]))

    resp.raise_for_status()


def main(args):
    parser = argparse.ArgumentParser(prog="twine register")
    settings.Settings.register_argparse_arguments(parser)
    parser.add_argument(
        "package",
        metavar="package",
        help="File from which we read the package metadata.",
    )

    args = parser.parse_args(args)
    register_settings = settings.Settings.from_argparse(args)

    # Call the register function with the args from the command line
    register(register_settings, args.package)
