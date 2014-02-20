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
import time

import invoke

import requests


JENKINS_URL = "http://jenkins.cryptography.io/job/cryptography-wheel-builder"


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
            break
        time.sleep(0.1)


@invoke.task
def release(version):
    """
    ``version`` should be a string like '0.4' or '1.0'.
    """
    invoke.run("git tag -s {0}".format(version))
    invoke.run("git push --tags")

    invoke.run("python setup.py sdist")
    invoke.run("twine upload -s dist/cryptography-{0}*".format(version))

    token = getpass.getpass("Input the Jenkins token")
    response = requests.post(
        "{0}/build".format(JENKINS_URL),
        params={
            "token": token,
            "cause": "Building wheels for {0}".format(version)
        }
    )
    response.raise_for_status()
    wait_for_build_completed()
