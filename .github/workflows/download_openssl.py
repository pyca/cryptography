# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import io
import os
import sys
import time
import zipfile

import requests

from urllib3.util.retry import Retry


def get_response(session, url, token):
    # Retry on non-502s
    for i in range(5):
        try:
            response = session.get(
                url, headers={"Authorization": "token " + token}
            )
        except (
            requests.exceptions.ChunkedEncodingError,
            requests.exceptions.ConnectTimeout,
        ) as e:
            print("Exception ({}) fetching {}, retrying".format(e, url))
            time.sleep(2)
            continue
        if response.status_code != 200:
            print(
                "HTTP error ({}) fetching {}, retrying".format(
                    response.status_code, url
                )
            )
            time.sleep(2)
            continue
        return response
    response = session.get(url, headers={"Authorization": "token " + token})
    if response.status_code != 200:
        raise ValueError(
            "Got HTTP {} fetching {}: ".format(response.status_code, url)
        )
    return response


def main(platform, target):
    if platform == "windows":
        workflow = "build-windows-openssl.yml"
        path = "C:/"
    elif platform == "macos":
        workflow = "build-macos-openssl.yml"
        path = os.environ["HOME"]
    else:
        raise ValueError("Invalid platform")

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=Retry())
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    token = os.environ["GITHUB_TOKEN"]
    print("Looking for: {}".format(target))
    runs_url = (
        "https://api.github.com/repos/pyca/infra/actions/workflows/"
        "{}/runs?branch=main&status=success".format(workflow)
    )

    response = get_response(session, runs_url, token).json()
    artifacts_url = response["workflow_runs"][0]["artifacts_url"]
    response = get_response(session, artifacts_url, token).json()
    for artifact in response["artifacts"]:
        if artifact["name"] == target:
            print("Found artifact")
            response = get_response(
                session, artifact["archive_download_url"], token
            )
            zipfile.ZipFile(io.BytesIO(response.content)).extractall(
                os.path.join(path, artifact["name"])
            )
            return
    raise ValueError("Didn't find {} in {}".format(target, response))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
