# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import getpass
import glob
import json
import os
import subprocess
import tempfile
import time
import zipfile

from azure.devops.connection import Connection
from azure.devops.v5_1.build.models import Build

import click

from msrest.authentication import BasicAuthentication


def run(*args, **kwargs):
    print("[running] {0}".format(list(args)))
    subprocess.check_call(list(args), **kwargs)


def wait_for_build_completed_azure(build_client, build_id):
    while True:
        build = build_client.get_build("cryptography", build_id)
        if build.finish_time is not None:
            break
        time.sleep(3)


def download_artifacts_azure(build_client, build_id):
    artifacts = build_client.get_artifacts("cryptography", build_id)
    paths = []
    for artifact in artifacts:
        contents = build_client.get_artifact_content_zip(
            "cryptography", build_id, artifact.name
        )
        with tempfile.NamedTemporaryFile() as f:
            for chunk in contents:
                f.write(chunk)
            f.flush()
            with zipfile.ZipFile(f.name) as z:
                for name in z.namelist():
                    if not name.endswith(".whl"):
                        continue
                    p = z.open(name)
                    out_path = os.path.join(
                        os.path.dirname(__file__),
                        "dist",
                        os.path.basename(name),
                    )
                    with open(out_path, "wb") as f:
                        f.write(p.read())
                    paths.append(out_path)
    return paths


def build_wheels_azure(version):
    token = getpass.getpass("Azure personal access token: ")
    credentials = BasicAuthentication("", token)
    connection = Connection(
        base_url="https://dev.azure.com/pyca", creds=credentials
    )
    build_client = connection.clients.get_build_client()
    [definition] = build_client.get_definitions(
        "cryptography", "wheel builder"
    )
    build_description = Build(
        definition=definition,
        parameters=json.dumps({"BUILD_VERSION": version}),
    )
    build = build_client.queue_build(
        project="cryptography", build=build_description
    )
    wait_for_build_completed_azure(build_client, build.id)
    return download_artifacts_azure(build_client, build.id)


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

    azure_wheel_paths = build_wheels_azure(version)
    run("twine", "upload", *azure_wheel_paths)


if __name__ == "__main__":
    release()
