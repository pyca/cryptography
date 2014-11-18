# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import getpass
import os
import time

import invoke

import requests


JENKINS_URL = "https://jenkins.cryptography.io/job/cryptography-wheel-builder"


def wait_for_build_completed(session):
    while True:
        response = session.get(
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


def download_artifacts(session):
    response = session.get(
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
        response = session.get(
            run["url"] + "api/json/",
            headers={
                "Accept": "application/json",
            }
        )
        response.raise_for_status()
        for artifact in response.json()["artifacts"]:
            response = session.get(
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
    invoke.run("git tag -s {0} -m '{0} release'".format(version))
    invoke.run("git push --tags")

    invoke.run("python setup.py sdist")
    invoke.run("cd vectors/ && python setup.py sdist bdist_wheel")

    invoke.run(
        "twine upload -s dist/cryptography-{0}* "
        "vectors/dist/cryptography_vectors-{0}*".format(version)
    )

    session = requests.Session()

    # This tells the CDN to delete the cached response for the URL. We do this
    # so that the Jenkins builders will see the new sdist immediately when they
    # go to build the wheels.
    response = session.request(
        "PURGE", "https://pypi.python.org/simple/cryptography/"
    )
    response.raise_for_status()

    username = getpass.getpass("Input the GitHub/Jenkins username: ")
    token = getpass.getpass("Input the Jenkins token: ")
    response = session.post(
        "{0}/build".format(JENKINS_URL),
        auth=requests.auth.HTTPBasicAuth(
            username, token
        ),
        params={
            "cause": "Building wheels for {0}".format(version)
        }
    )
    response.raise_for_status()
    wait_for_build_completed(session)
    paths = download_artifacts(session)
    invoke.run("twine upload {0}".format(" ".join(paths)))
