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
import sys
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from typing import cast

import requests
import requests_toolbelt
import tqdm
import urllib3
from requests import adapters
from requests_toolbelt.utils import user_agent

import twine
from twine import package as package_file

KEYWORDS_TO_NOT_FLATTEN = {"gpg_signature", "content"}

LEGACY_PYPI = "https://pypi.python.org/"
LEGACY_TEST_PYPI = "https://testpypi.python.org/"
WAREHOUSE = "https://upload.pypi.org/"
OLD_WAREHOUSE = "https://upload.pypi.io/"
TEST_WAREHOUSE = "https://test.pypi.org/"
WAREHOUSE_WEB = "https://pypi.org/"


class ProgressBar(tqdm.tqdm):
    def update_to(self, n: int) -> None:
        """Update the bar in the way compatible with requests-toolbelt.

        This is identical to tqdm.update, except ``n`` will be the current
        value - not the delta as tqdm expects.
        """
        self.update(n - self.n)  # will also do self.n = n


class Repository:
    def __init__(
        self,
        repository_url: str,
        username: Optional[str],
        password: Optional[str],
        disable_progress_bar: bool = False,
    ) -> None:
        self.url = repository_url

        self.session = requests.session()
        # requests.Session.auth should be Union[None, Tuple[str, str], ...]
        # But username or password could be None
        # See TODO for utils.RepositoryConfig
        self.session.auth = (
            (username or "", password or "") if username or password else None
        )
        self.session.headers["User-Agent"] = self._make_user_agent_string()
        for scheme in ("http://", "https://"):
            self.session.mount(scheme, self._make_adapter_with_retries())

        # Working around https://github.com/python/typing/issues/182
        self._releases_json_data: Dict[str, Dict[str, Any]] = {}
        self.disable_progress_bar = disable_progress_bar

    @staticmethod
    def _make_adapter_with_retries() -> adapters.HTTPAdapter:
        retry = urllib3.Retry(
            connect=5,
            total=10,
            method_whitelist=["GET"],
            status_forcelist=[500, 501, 502, 503],
        )
        return adapters.HTTPAdapter(max_retries=retry)

    @staticmethod
    def _make_user_agent_string() -> str:
        from twine import cli

        dependencies = cli.list_dependencies_and_versions()
        user_agent_string = (
            user_agent.UserAgentBuilder("twine", twine.__version__)
            .include_extras(dependencies)
            .include_implementation()
            .build()
        )

        return cast(str, user_agent_string)

    def close(self) -> None:
        self.session.close()

    @staticmethod
    def _convert_data_to_list_of_tuples(data: Dict[str, Any]) -> List[Tuple[str, Any]]:
        data_to_send = []
        for key, value in data.items():
            if key in KEYWORDS_TO_NOT_FLATTEN or not isinstance(value, (list, tuple)):
                data_to_send.append((key, value))
            else:
                for item in value:
                    data_to_send.append((key, item))
        return data_to_send

    def set_certificate_authority(self, cacert: Optional[str]) -> None:
        if cacert:
            self.session.verify = cacert

    def set_client_certificate(self, clientcert: Optional[str]) -> None:
        if clientcert:
            self.session.cert = clientcert

    def register(self, package: package_file.PackageFile) -> requests.Response:
        data = package.metadata_dictionary()
        data.update({":action": "submit", "protocol_version": "1"})

        print(f"Registering {package.basefilename}")

        data_to_send = self._convert_data_to_list_of_tuples(data)
        encoder = requests_toolbelt.MultipartEncoder(data_to_send)
        resp = self.session.post(
            self.url,
            data=encoder,
            allow_redirects=False,
            headers={"Content-Type": encoder.content_type},
        )
        # Bug 28. Try to silence a ResourceWarning by releasing the socket.
        resp.close()
        return resp

    def _upload(self, package: package_file.PackageFile) -> requests.Response:
        data = package.metadata_dictionary()
        data.update(
            {
                # action
                ":action": "file_upload",
                "protocol_version": "1",
            }
        )

        data_to_send = self._convert_data_to_list_of_tuples(data)

        print(f"Uploading {package.basefilename}")

        with open(package.filename, "rb") as fp:
            data_to_send.append(
                ("content", (package.basefilename, fp, "application/octet-stream"))
            )
            encoder = requests_toolbelt.MultipartEncoder(data_to_send)
            with ProgressBar(
                total=encoder.len,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                miniters=1,
                file=sys.stdout,
                disable=self.disable_progress_bar,
            ) as bar:
                monitor = requests_toolbelt.MultipartEncoderMonitor(
                    encoder, lambda monitor: bar.update_to(monitor.bytes_read)
                )

                resp = self.session.post(
                    self.url,
                    data=monitor,
                    allow_redirects=False,
                    headers={"Content-Type": monitor.content_type},
                )

        return resp

    def upload(
        self, package: package_file.PackageFile, max_redirects: int = 5
    ) -> requests.Response:
        number_of_redirects = 0
        while number_of_redirects < max_redirects:
            resp = self._upload(package)

            if resp.status_code == requests.codes.OK:
                return resp
            if 500 <= resp.status_code < 600:
                number_of_redirects += 1
                print(
                    'Received "{status_code}: {reason}" Package upload '
                    "appears to have failed.  Retry {retry} of "
                    "{max_redirects}".format(
                        status_code=resp.status_code,
                        reason=resp.reason,
                        retry=number_of_redirects,
                        max_redirects=max_redirects,
                    )
                )
            else:
                return resp

        return resp

    def package_is_uploaded(
        self, package: package_file.PackageFile, bypass_cache: bool = False
    ) -> bool:
        # NOTE(sigmavirus24): Not all indices are PyPI and pypi.io doesn't
        # have a similar interface for finding the package versions.
        if not self.url.startswith((LEGACY_PYPI, WAREHOUSE, OLD_WAREHOUSE)):
            return False

        safe_name = package.safe_name
        releases = None

        if not bypass_cache:
            releases = self._releases_json_data.get(safe_name)

        if releases is None:
            url = "{url}pypi/{package}/json".format(package=safe_name, url=LEGACY_PYPI)
            headers = {"Accept": "application/json"}
            response = self.session.get(url, headers=headers)
            if response.status_code == 200:
                releases = response.json()["releases"]
            else:
                releases = {}
            self._releases_json_data[safe_name] = releases

        packages = releases.get(package.metadata.version, [])

        for uploaded_package in packages:
            if uploaded_package["filename"] == package.basefilename:
                return True

        return False

    def release_urls(self, packages: List[package_file.PackageFile]) -> Set[str]:
        if self.url.startswith(WAREHOUSE):
            url = WAREHOUSE_WEB
        elif self.url.startswith(TEST_WAREHOUSE):
            url = TEST_WAREHOUSE
        else:
            return set()

        return {
            "{}project/{}/{}/".format(url, package.safe_name, package.metadata.version)
            for package in packages
        }

    def verify_package_integrity(self, package: package_file.PackageFile) -> None:
        # TODO(sigmavirus24): Add a way for users to download the package and
        # check it's hash against what it has locally.
        pass
