# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import getpass
import glob
import io
import os
import subprocess
import time

import click

from clint.textui.progress import Bar as ProgressBar

import requests


JENKINS_URL = (
    "https://ci.cryptography.io/job/cryptography-support-jobs/"
    "job/wheel-builder"
)


def run(*args, **kwargs):
    print("[running] {0}".format(list(args)))
    subprocess.check_call(list(args), **kwargs)


def wait_for_build_completed(session):
    # Wait 20 seconds before actually checking if the build is complete, to
    # ensure that it had time to really start.
    time.sleep(20)
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
    json_response = response.json()
    assert not json_response["building"]
    assert json_response["result"] == "SUCCESS"

    paths = []

    for artifact in json_response["artifacts"]:
        response = session.get(
            "{0}artifact/{1}".format(
                json_response["url"], artifact["relativePath"]
            ), stream=True
        )
        assert response.headers["content-length"]
        print("Downloading {0}".format(artifact["fileName"]))
        bar = ProgressBar(
            expected_size=int(response.headers["content-length"]),
            filled_char="="
        )
        content = io.BytesIO()
        for data in response.iter_content(chunk_size=8192):
            content.write(data)
            bar.show(content.tell())
        assert bar.expected_size == content.tell()
        bar.done()
        out_path = os.path.join(
            os.path.dirname(__file__),
            "dist",
            artifact["fileName"],
        )
        with open(out_path, "wb") as f:
            f.write(content.getvalue())
        paths.append(out_path)
    return paths


@click.command()
@click.argument("version")
def release(version):
    """
    ``version`` should be a string like '0.4' or '1.0'.
    """
    run("git", "tag", "-s", version, "-m", "{0} release".format(version))
    run("git", "push", "--tags")

    run("python", "setup.py", "sdist")
    run("python", "setup.py", "sdist", "bdist_wheel", cwd="vectors/")

    packages = (
        glob.glob("dist/cryptography-{0}*".format(version)) +
        glob.glob("vectors/dist/cryptography_vectors-{0}*".format(version))
    )
    run("twine", "upload", "-s", *packages)

    session = requests.Session()

    token = getpass.getpass("Input the Jenkins token: ")
    response = session.get(
        "{0}/buildWithParameters".format(JENKINS_URL),
        params={
            "token": token,
            "BUILD_VERSION": version,
            "cause": "Building wheels for {0}".format(version)
        }
    )
    response.raise_for_status()
    wait_for_build_completed(session)
    paths = download_artifacts(session)
    run("twine", "upload", *paths)


if __name__ == "__main__":
    release()
