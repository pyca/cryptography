import io
import os
import sys
import zipfile

import requests


# TODO: Switch to master
BRANCH = "openssl-windows-github-actions"
RUNS_URL = (
    "https://api.github.com/repos/pyca/infra/actions/workflows/"
    "build-openssl.yml/runs?branch={}&status=success".format(BRANCH)
)


def get_response(url, token):
    response = requests.get(url, headers={"Authorization": "token " + token})
    if response.status_code != 200:
        raise ValueError("Got HTTP {} fetching {}: ".format(
            response.code, url, response.content
        ))
    return response


def main(target):
    token = os.environ["GITHUB_TOKEN"]
    print("Looking for: {}".format(target))

    response = get_response(RUNS_URL, token).json()
    artifacts_url = response["workflow_runs"][0]["artifacts_url"]
    response = get_response(artifacts_url, token).json()
    for artifact in response["artifacts"]:
        if artifact["name"] == target:
            print("Found artifact")
            response = get_response(
                artifact["archive_download_url"], token
            )
            zipfile.ZipFile(io.BytesIO(response.content)).extractall(
                "C:/{}".format(artifact["name"])
            )
            return


if __name__ == "__main__":
    main(sys.argv[1])
