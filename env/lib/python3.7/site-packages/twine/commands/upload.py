# Copyright 2013 Donald Stufft
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
import os.path

from twine.commands import _find_dists
from twine.package import PackageFile
from twine import exceptions
from twine import settings
from twine import utils


def skip_upload(response, skip_existing, package):
    filename = package.basefilename
    # NOTE(sigmavirus24): Old PyPI returns the first message while Warehouse
    # returns the latter. This papers over the differences.
    msg_400 = ('A file named "{0}" already exists for'.format(filename),
               'File already exists')
    msg_403 = 'Not enough permissions to overwrite artifact'
    # NOTE(sigmavirus24): PyPI presently returns a 400 status code with the
    # error message in the reason attribute. Other implementations return a
    # 409 or 403 status code. We only want to skip an upload if:
    # 1. The user has told us to skip existing packages (skip_existing is
    #    True) AND
    # 2. a) The response status code is 409 OR
    # 2. b) The response status code is 400 AND it has a reason that matches
    #       what we expect PyPI to return to us. OR
    # 2. c) The response status code is 403 AND the text matches what we
    #       expect Artifactory to return to us.
    return (skip_existing and (response.status_code == 409 or
            (response.status_code == 400 and
             response.reason.startswith(msg_400)) or
            (response.status_code == 403 and msg_403 in response.text)))


def upload(upload_settings, dists):
    dists = _find_dists(dists)

    # Determine if the user has passed in pre-signed distributions
    signatures = dict(
        (os.path.basename(d), d) for d in dists if d.endswith(".asc")
    )
    uploads = [i for i in dists if not i.endswith(".asc")]
    upload_settings.check_repository_url()
    repository_url = upload_settings.repository_config['repository']

    print("Uploading distributions to {0}".format(repository_url))

    repository = upload_settings.create_repository()

    for filename in uploads:
        package = PackageFile.from_filename(filename, upload_settings.comment)
        skip_message = (
            "  Skipping {0} because it appears to already exist".format(
                package.basefilename)
        )

        # Note: The skip_existing check *needs* to be first, because otherwise
        #       we're going to generate extra HTTP requests against a hardcoded
        #       URL for no reason.
        if (upload_settings.skip_existing and
                repository.package_is_uploaded(package)):
            print(skip_message)
            continue

        signed_name = package.signed_basefilename
        if signed_name in signatures:
            package.add_gpg_signature(signatures[signed_name], signed_name)
        elif upload_settings.sign:
            package.sign(upload_settings.sign_with, upload_settings.identity)

        resp = repository.upload(package)

        # Bug 92. If we get a redirect we should abort because something seems
        # funky. The behaviour is not well defined and redirects being issued
        # by PyPI should never happen in reality. This should catch malicious
        # redirects as well.
        if resp.is_redirect:
            raise exceptions.RedirectDetected(
                ('"{0}" attempted to redirect to "{1}" during upload.'
                 ' Aborting...').format(repository_url,
                                        resp.headers["location"]))

        if skip_upload(resp, upload_settings.skip_existing, package):
            print(skip_message)
            continue
        utils.check_status_code(resp, upload_settings.verbose)

    # Bug 28. Try to silence a ResourceWarning by clearing the connection
    # pool.
    repository.close()


def main(args):
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

    args = parser.parse_args(args)
    upload_settings = settings.Settings.from_argparse(args)

    # Call the upload function with the arguments from the command line
    return upload(upload_settings, args.dists)
