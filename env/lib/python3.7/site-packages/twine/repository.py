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

import sys

from tqdm import tqdm

import requests
from requests import adapters
from requests import codes
from requests.packages.urllib3 import util
from requests_toolbelt.multipart import (
    MultipartEncoder, MultipartEncoderMonitor
)
from requests_toolbelt.utils import user_agent

import twine

KEYWORDS_TO_NOT_FLATTEN = set(["gpg_signature", "content"])

LEGACY_PYPI = 'https://pypi.python.org/'
LEGACY_TEST_PYPI = 'https://testpypi.python.org/'
WAREHOUSE = 'https://upload.pypi.org/'
OLD_WAREHOUSE = 'https://upload.pypi.io/'


class ProgressBar(tqdm):
    def update_to(self, n):
        """Update the bar in the way compatible with requests-toolbelt.

        This is identical to tqdm.update, except ``n`` will be the current
        value - not the delta as tqdm expects.
        """
        self.update(n - self.n)  # will also do self.n = n


class Repository(object):
    def __init__(self, repository_url, username, password):
        self.url = repository_url
        self.session = requests.session()
        self.session.auth = (username, password)
        self.session.headers['User-Agent'] = self._make_user_agent_string()
        for scheme in ('http://', 'https://'):
            self.session.mount(scheme, self._make_adapter_with_retries())
        self._releases_json_data = {}

    @staticmethod
    def _make_adapter_with_retries():
        retry = util.Retry(
            connect=5,
            total=10,
            method_whitelist=['GET'],
            status_forcelist=[500, 501, 502, 503],
        )
        return adapters.HTTPAdapter(max_retries=retry)

    @staticmethod
    def _make_user_agent_string():
        from twine import cli
        dependencies = cli.list_dependencies_and_versions()
        return user_agent.UserAgentBuilder(
                'twine', twine.__version__,
            ).include_extras(
                dependencies
            ).include_implementation().build()

    def close(self):
        self.session.close()

    @staticmethod
    def _convert_data_to_list_of_tuples(data):
        data_to_send = []
        for key, value in data.items():
            if (key in KEYWORDS_TO_NOT_FLATTEN or
                    not isinstance(value, (list, tuple))):
                data_to_send.append((key, value))
            else:
                for item in value:
                    data_to_send.append((key, item))
        return data_to_send

    def set_certificate_authority(self, cacert):
        if cacert:
            self.session.verify = cacert

    def set_client_certificate(self, clientcert):
        if clientcert:
            self.session.cert = clientcert

    def register(self, package):
        data = package.metadata_dictionary()
        data.update({
            ":action": "submit",
            "protocol_version": "1",
        })

        print("Registering {0}".format(package.basefilename))

        data_to_send = self._convert_data_to_list_of_tuples(data)
        encoder = MultipartEncoder(data_to_send)
        resp = self.session.post(
            self.url,
            data=encoder,
            allow_redirects=False,
            headers={'Content-Type': encoder.content_type},
        )
        # Bug 28. Try to silence a ResourceWarning by releasing the socket.
        resp.close()
        return resp

    def _upload(self, package):
        data = package.metadata_dictionary()
        data.update({
            # action
            ":action": "file_upload",
            "protocol_version": "1",
        })

        data_to_send = self._convert_data_to_list_of_tuples(data)

        print("Uploading {0}".format(package.basefilename))

        with open(package.filename, "rb") as fp:
            data_to_send.append((
                "content",
                (package.basefilename, fp, "application/octet-stream"),
            ))
            encoder = MultipartEncoder(data_to_send)
            with ProgressBar(total=encoder.len,
                             unit='B', unit_scale=True, unit_divisor=1024,
                             miniters=1, file=sys.stdout) as bar:
                monitor = MultipartEncoderMonitor(
                    encoder, lambda monitor: bar.update_to(monitor.bytes_read)
                )

                resp = self.session.post(
                    self.url,
                    data=monitor,
                    allow_redirects=False,
                    headers={'Content-Type': monitor.content_type},
                )

        return resp

    def upload(self, package, max_redirects=5):
        number_of_redirects = 0
        while number_of_redirects < max_redirects:
            resp = self._upload(package)

            if resp.status_code == codes.OK:
                return resp
            if 500 <= resp.status_code < 600:
                number_of_redirects += 1
                print('Received "{status_code}: {reason}" Package upload '
                      'appears to have failed.  Retry {retry} of 5'.format(
                          status_code=resp.status_code,
                          reason=resp.reason,
                          retry=number_of_redirects,
                      ))
            else:
                return resp

        return resp

    def package_is_uploaded(self, package, bypass_cache=False):
        # NOTE(sigmavirus24): Not all indices are PyPI and pypi.io doesn't
        # have a similar interface for finding the package versions.
        if not self.url.startswith((LEGACY_PYPI, WAREHOUSE, OLD_WAREHOUSE)):
            return False

        safe_name = package.safe_name
        releases = None

        if not bypass_cache:
            releases = self._releases_json_data.get(safe_name)

        if releases is None:
            url = '{url}pypi/{package}/json'.format(package=safe_name,
                                                    url=LEGACY_PYPI)
            headers = {'Accept': 'application/json'}
            response = self.session.get(url, headers=headers)
            if response.status_code == 200:
                releases = response.json()['releases']
            else:
                releases = {}
            self._releases_json_data[safe_name] = releases

        packages = releases.get(package.metadata.version, [])

        for uploaded_package in packages:
            if uploaded_package['filename'] == package.basefilename:
                return True

        return False

    def verify_package_integrity(self, package):
        # TODO(sigmavirus24): Add a way for users to download the package and
        # check it's hash against what it has locally.
        pass
