# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import getpass
import glob
import io
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

import requests


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


def build_wheels_azure(token, version):
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


def wait_for_build_complete_github_actions(session, token, run_url):
    while True:
        response = session.get(run_url, headers={
            "Content-Type": "application/json",
            "Authorization": "token {}".format(token),
        })
        response.raise_for_status()
        if response.json()["conclusion"] is not None:
            break
        time.sleep(3)


def download_artifacts_github_actions(session, token, run_url):
    response = session.get(run_url, headers={
        "Content-Type": "application/json",
        "Authorization": "token {}".format(token),
    })
    response.raise_for_status()

    response = session.get(response.json()["artifacts_url"], headers={
        "Content-Type": "application/json",
        "Authorization": "token {}".format(token),
    })
    response.raise_for_status()
    paths = []
    for artifact in response.json()["artifacts"]:
        response = session.get(artifact["archive_download_url"], headers={
            "Content-Type": "application/json",
            "Authorization": "token {}".format(token),
        })
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
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


def build_github_actions_wheels(token, version):
    session = requests.Session()

    response = session.post(
        "https://api.github.com/repos/pyca/cryptography/dispatches",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/vnd.github.everest-preview+json",
            "Authorization": "token {}".format(token),
        },
        data=json.dumps({
            "event_type": "wheel-builder",
            "client_payload": {
                "BUILD_VERSION": version,
            },
        }),
    )
    response.raise_for_status()

    response = session.get(
        (
            "https://api.github.com/repos/pyca/cryptography/actions/workflows/"
            "wheel-builder.yml/runs?event=repository_dispatch"
        ),
        headers={
            "Content-Type": "application/json",
            "Authorization": "token {}".format(token),
        },
    )
    response.raise_for_status()
    run_url = response.json()["workflow_runs"][0]["url"]
    wait_for_build_complete_github_actions(session, token, run_url)
    return download_artifacts_github_actions(session, token, run_url)


@click.command()
@click.argument("version")
def release(version):
    """
    ``version`` should be a string like '0.4' or '1.0'.
    """
    azure_token = getpass.getpass("Azure personal access token: ")
    github_token = getpass.getpass("Github person access token: ")

    run("git", "tag", "-s", version, "-m", "{0} release".format(version))
    run("git", "push", "--tags")

    run("python", "setup.py", "sdist")
    run("python", "setup.py", "sdist", "bdist_wheel", cwd="vectors/")

    packages = (
        glob.glob("dist/cryptography-{0}*".format(version)) +
        glob.glob("vectors/dist/cryptography_vectors-{0}*".format(version))
    )
    run("twine", "upload", "-s", *packages)

    azure_wheel_paths = build_wheels_azure(azure_token, version)
    github_actions_wheel_paths = build_github_actions_wheels(
        github_token, version
    )
    run("twine", "upload", *(azure_wheel_paths, github_actions_wheel_paths))


if __name__ == "__main__":
    release()
