# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import getpass
import io
import os
import subprocess
import time
import typing
import urllib
import zipfile

import click
import requests


def run(*args: str) -> None:
    print("[running] {0}".format(list(args)))
    subprocess.check_call(list(args))


def wait_for_build_complete_github_actions(
    session: requests.Session, token: str, run_url: str
) -> None:
    while True:
        response = session.get(
            run_url,
            headers={
                "Content-Type": "application/json",
                "Authorization": "token {}".format(token),
            },
        )
        response.raise_for_status()
        if response.json()["conclusion"] is not None:
            break
        time.sleep(3)


def download_artifacts_github_actions(
    session: requests.Session, token: str, run_url: str
) -> typing.List[str]:
    response = session.get(
        run_url,
        headers={
            "Content-Type": "application/json",
            "Authorization": "token {}".format(token),
        },
    )
    response.raise_for_status()

    response = session.get(
        response.json()["artifacts_url"],
        headers={
            "Content-Type": "application/json",
            "Authorization": "token {}".format(token),
        },
    )
    response.raise_for_status()
    paths = []
    for artifact in response.json()["artifacts"]:
        response = session.get(
            artifact["archive_download_url"],
            headers={
                "Content-Type": "application/json",
                "Authorization": "token {}".format(token),
            },
        )
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            for name in z.namelist():
                if not name.endswith(".whl") and not name.endswith(".tar.gz"):
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


def fetch_github_actions_artifacts(
    token: str, version: str
) -> typing.List[str]:
    session = requests.Session()

    workflow_runs = []

    # There is a race condition where no workflow run has triggered after
    # pushing the tag, so loop until we get the run.
    while True:
        response = session.get(
            (
                f"https://api.github.com/repos/pyca/cryptography/actions"
                f"/workflows/wheel-builder.yml/runs?event=push&"
                f"branch={version}"
            ),
            headers={
                "Content-Type": "application/json",
                "Authorization": "token {}".format(token),
            },
        )
        response.raise_for_status()
        workflow_runs = response.json()["workflow_runs"]
        if len(workflow_runs) > 0:
            break
        time.sleep(3)

    run_url: str = workflow_runs[0]["url"]
    wait_for_build_complete_github_actions(session, token, run_url)
    return download_artifacts_github_actions(session, token, run_url)


def wait_for_build_complete_circleci(
    session: requests.Session, token: str, pipeline_id: str
) -> None:
    while True:
        response = session.get(
            f"https://circleci.com/api/v2/pipeline/{pipeline_id}/workflow",
            headers={
                "Circle-Token": token,
            },
        )
        response.raise_for_status()
        status = response.json()["items"][0]["status"]
        if status == "success":
            break
        elif status not in ("running", "on_hold", "not_run"):
            raise ValueError(f"CircleCI build failed with status {status}")
        time.sleep(3)


def download_artifacts_circleci(
    session: requests.Session, urls: typing.List[str]
) -> typing.List[str]:
    paths = []
    for url in urls:
        name = os.path.basename(urllib.parse.urlparse(url).path)
        response = session.get(url)
        out_path = os.path.join(
            os.path.dirname(__file__),
            "dist",
            os.path.basename(name),
        )
        with open(out_path, "wb") as f:
            f.write(response.content)
        paths.append(out_path)
    return paths


def fetch_circleci_artifacts(token: str, version: str) -> typing.List[str]:
    session = requests.Session()

    response = session.get(
        "https://circleci.com/api/v2/pipeline?org-slug=gh/pyca",
        headers={"Circle-Token": token},
    )
    response.raise_for_status()
    pipeline_id = None
    for item in response.json()["items"]:
        if item["project_slug"] == "gh/pyca/cryptography":
            if item["vcs"].get("tag", None) == version:
                pipeline_id = item["id"]
                break

    if pipeline_id is None:
        raise ValueError(f"Could not find a pipeline for version {version}")

    wait_for_build_complete_circleci(session, token, pipeline_id)
    urls = fetch_circleci_artifact_urls(session, token, pipeline_id)
    return download_artifacts_circleci(session, urls)


def fetch_circleci_artifact_urls(
    session: requests.Session, token: str, pipeline_id: str
) -> typing.List[str]:
    response = session.get(
        f"https://circleci.com/api/v2/pipeline/{pipeline_id}/workflow",
        headers={"Circle-Token": token},
    )
    response.raise_for_status()
    workflow_id = response.json()["items"][0]["id"]
    job_response = session.get(
        f"https://circleci.com/api/v2/workflow/{workflow_id}/job",
        headers={"Circle-Token": token},
    )
    job_response.raise_for_status()
    artifact_urls = []
    for job in job_response.json()["items"]:
        urls = fetch_circleci_artifact_url_from_job(
            session, token, job["job_number"]
        )
        artifact_urls.extend(urls)

    return artifact_urls


def fetch_circleci_artifact_url_from_job(
    session: requests.Session, token: str, job: str
) -> typing.List[str]:
    response = session.get(
        f"https://circleci.com/api/v2/project/gh/pyca/cryptography/"
        f"{job}/artifacts",
        headers={"Circle-Token": token},
    )
    response.raise_for_status()
    urls = []
    for item in response.json()["items"]:
        url = item.get("url", None)
        if url is not None:
            urls.append(url)

    return urls


@click.command()
@click.argument("version")
def release(version: str) -> None:
    """
    ``version`` should be a string like '0.4' or '1.0'.
    """
    print(
        f"Create a new GH PAT with only actions permissions at: "
        f"https://github.com/settings/tokens/new?"
        f"description={version}&scopes=repo"
    )
    print(
        "Get a CircleCI token at: "
        "https://app.circleci.com/settings/user/tokens"
    )
    github_token = getpass.getpass("Github person access token: ")
    circle_token = getpass.getpass("CircleCI token: ")

    # Tag and push the tag (this will trigger the wheel builder in Actions)
    run("git", "tag", "-s", version, "-m", f"{version} release")
    run("git", "push", "--tags")

    os.mkdir(os.path.join(os.path.dirname(__file__), "dist"))

    # Wait for Actions to complete and download the wheels
    github_actions_artifact_paths = fetch_github_actions_artifacts(
        github_token, version
    )
    # Download wheels from CircleCI
    circle_artifact_paths = fetch_circleci_artifacts(circle_token, version)

    artifact_paths = github_actions_artifact_paths + circle_artifact_paths

    # Upload wheels and sdist
    run("twine", "upload", *artifact_paths)


if __name__ == "__main__":
    release()
