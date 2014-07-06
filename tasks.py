# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import getpass
import os
import time

import invoke

import requests


JENKINS_URL = "https://jenkins.cryptography.io/job/cryptography-wheel-builder"


def wait_for_build_completed():
    while True:
        response = requests.get(
            "{0}/lastBuild/api/json/".format(JENKINS_URL),
            headers={
                "Accept": "application/json",
            }
        )
        response.raise_for_status()
        if not response.json()["building"]:
            assert response.json()["result"] == "SUCCESS"
            break
        time.sleep(0.1)


def download_artifacts():
    response = requests.get(
        "{0}/lastBuild/api/json/".format(JENKINS_URL),
        headers={
            "Accept": "application/json"
        }
    )
    response.raise_for_status()
    assert not response.json()["building"]
    assert response.json()["result"] == "SUCCESS"

    paths = []

    for run in response.json()["runs"]:
        response = requests.get(
            run["url"] + "api/json/",
            headers={
                "Accept": "application/json",
            }
        )
        response.raise_for_status()
        for artifact in response.json()["artifacts"]:
            response = requests.get(
                "{0}artifact/{1}".format(run["url"], artifact["relativePath"])
            )
            out_path = os.path.join(
                os.path.dirname(__file__),
                "dist",
                artifact["fileName"],
            )
            with open(out_path, "wb") as f:
                f.write(response.content)
            paths.append(out_path)
    return paths


@invoke.task
def release(version):
    """
    ``version`` should be a string like '0.4' or '1.0'.
    """
    invoke.run("git tag -s {0}".format(version))
    invoke.run("git push --tags")

    invoke.run("python setup.py sdist")
    invoke.run("cd vectors/ && python setup.py sdist bdist_wheel")

    invoke.run(
        "twine upload -s dist/cryptography-{0}* "
        "vectors/dist/cryptography_vectors-{0}*".format(version)
    )

    username = getpass.getpass("Input the GitHub/Jenkins username: ")
    token = getpass.getpass("Input the Jenkins token: ")
    response = requests.post(
        "{0}/build".format(JENKINS_URL),
        auth=requests.auth.HTTPBasicAuth(
            username, token
        ),
        params={
            "cause": "Building wheels for {0}".format(version)
        }
    )
    response.raise_for_status()
    wait_for_build_completed()
    paths = download_artifacts()
    invoke.run("twine upload {0}".format(" ".join(paths)))
