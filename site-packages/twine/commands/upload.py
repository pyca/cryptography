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
import argparse
import os.path
from typing import Dict
from typing import List
from typing import cast

import requests

from twine import commands
from twine import exceptions
from twine import package as package_file
from twine import settings
from twine import utils


def skip_upload(
    response: requests.Response, skip_existing: bool, package: package_file.PackageFile
) -> bool:
    if not skip_existing:
        return False

    status = response.status_code
    reason = getattr(response, "reason", "").lower()
    text = getattr(response, "text", "").lower()

    # NOTE(sigmavirus24): PyPI presently returns a 400 status code with the
    # error message in the reason attribute. Other implementations return a
    # 403 or 409 status code.
    return (
        # pypiserver (https://pypi.org/project/pypiserver)
        status == 409
        # PyPI / TestPyPI
        or (status == 400 and "already exist" in reason)
        # Nexus Repository OSS (https://www.sonatype.com/nexus-repository-oss)
        or (status == 400 and "updating asset" in reason)
        # Artifactory (https://jfrog.com/artifactory/)
        or (status == 403 and "overwrite artifact" in text)
    )


def _make_package(
    filename: str, signatures: Dict[str, str], upload_settings: settings.Settings
) -> package_file.PackageFile:
    """Create and sign a package, based off of filename, signatures and settings."""
    package = package_file.PackageFile.from_filename(filename, upload_settings.comment)

    signed_name = package.signed_basefilename
    if signed_name in signatures:
        package.add_gpg_signature(signatures[signed_name], signed_name)
    elif upload_settings.sign:
        package.sign(upload_settings.sign_with, upload_settings.identity)

    if upload_settings.verbose:
        file_size = utils.get_file_size(package.filename)
        print(f"  {package.filename} ({file_size})")
        if package.gpg_signature:
            print(f"  Signed with {package.signed_filename}")

    return package


def upload(upload_settings: settings.Settings, dists: List[str]) -> None:
    dists = commands._find_dists(dists)
    # Determine if the user has passed in pre-signed distributions
    signatures = {os.path.basename(d): d for d in dists if d.endswith(".asc")}
    uploads = [i for i in dists if not i.endswith(".asc")]

    upload_settings.check_repository_url()
    repository_url = cast(str, upload_settings.repository_config["repository"])
    print(f"Uploading distributions to {repository_url}")

    packages_to_upload = [
        _make_package(filename, signatures, upload_settings) for filename in uploads
    ]

    repository = upload_settings.create_repository()
    uploaded_packages = []

    for package in packages_to_upload:
        skip_message = "  Skipping {} because it appears to already exist".format(
            package.basefilename
        )

        # Note: The skip_existing check *needs* to be first, because otherwise
        #       we're going to generate extra HTTP requests against a hardcoded
        #       URL for no reason.
        if upload_settings.skip_existing and repository.package_is_uploaded(package):
            print(skip_message)
            continue

        resp = repository.upload(package)

        # Bug 92. If we get a redirect we should abort because something seems
        # funky. The behaviour is not well defined and redirects being issued
        # by PyPI should never happen in reality. This should catch malicious
        # redirects as well.
        if resp.is_redirect:
            raise exceptions.RedirectDetected.from_args(
                repository_url, resp.headers["location"],
            )

        if skip_upload(resp, upload_settings.skip_existing, package):
            print(skip_message)
            continue

        utils.check_status_code(resp, upload_settings.verbose)

        uploaded_packages.append(package)

    release_urls = repository.release_urls(uploaded_packages)
    if release_urls:
        print("\nView at:")
        for url in release_urls:
            print(url)

    # Bug 28. Try to silence a ResourceWarning by clearing the connection
    # pool.
    repository.close()


def main(args: List[str]) -> None:
    parser = argparse.ArgumentParser(prog="twine upload")
    settings.Settings.register_argparse_arguments(parser)
    parser.add_argument(
        "dists",
        nargs="+",
        metavar="dist",
        help="The distribution files to upload to the repository "
        "(package index). Usually dist/* . May additionally contain "
        "a .asc file to include an existing signature with the "
        "file upload.",
    )

    parsed_args = parser.parse_args(args)
    upload_settings = settings.Settings.from_argparse(parsed_args)

    # Call the upload function with the arguments from the command line
    return upload(upload_settings, parsed_args.dists)
