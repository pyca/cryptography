# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import getpass
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
    kwargs.setdefault("stderr", subprocess.STDOUT)
    try:
        subprocess.check_output(list(args), **kwargs)
    except subprocess.CalledProcessError as e:
        # Reraise this with a different type so that str(e) is something with
        # stdout in it.
        raise Exception(e.cmd, e.returncode, e.output)


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

    run(
        "twine", "upload", "-s", "dist/cryptography-{0}*".format(version),
        "vectors/dist/cryptography_vectors-{0}*".format(version), shell=True
    )

    session = requests.Session()

    # This tells the CDN to delete the cached response for the URL. We do this
    # so that the Jenkins builders will see the new sdist immediately when they
    # go to build the wheels.
    response = session.request(
        "PURGE", "https://pypi.python.org/simple/cryptography/"
    )
    response.raise_for_status()

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
