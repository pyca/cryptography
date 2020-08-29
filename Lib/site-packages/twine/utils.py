# Copyright 2013 Donald Stufft
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import collections
import configparser
import functools
import os
import os.path
from typing import Any
from typing import Callable
from typing import DefaultDict
from typing import Dict
from typing import Optional
from typing import Sequence
from typing import Union
from urllib.parse import urlparse
from urllib.parse import urlunparse

import requests
import rfc3986

from twine import exceptions

# Shim for input to allow testing.
input_func = input

DEFAULT_REPOSITORY = "https://upload.pypi.org/legacy/"
TEST_REPOSITORY = "https://test.pypi.org/legacy/"

# TODO: In general, it seems to be assumed that the values retrieved from
# instances of this type aren't None, except for username and password.
# Type annotations would be cleaner if this were Dict[str, str], but that
# requires reworking the username/password handling, probably starting with
# get_userpass_value.
RepositoryConfig = Dict[str, Optional[str]]


def get_config(path: str = "~/.pypirc") -> Dict[str, RepositoryConfig]:
    # even if the config file does not exist, set up the parser
    # variable to reduce the number of if/else statements
    parser = configparser.RawConfigParser()

    # this list will only be used if index-servers
    # is not defined in the config file
    index_servers = ["pypi", "testpypi"]

    # default configuration for each repository
    defaults: RepositoryConfig = {"username": None, "password": None}

    # Expand user strings in the path
    path = os.path.expanduser(path)

    # Parse the rc file
    if os.path.isfile(path):
        parser.read(path)

        # Get a list of index_servers from the config file
        # format: https://packaging.python.org/specifications/pypirc/
        if parser.has_option("distutils", "index-servers"):
            index_servers = parser.get("distutils", "index-servers").split()

        for key in ["username", "password"]:
            if parser.has_option("server-login", key):
                defaults[key] = parser.get("server-login", key)

    config: DefaultDict[str, RepositoryConfig] = collections.defaultdict(
        lambda: defaults.copy()
    )

    # don't require users to manually configure URLs for these repositories
    config["pypi"]["repository"] = DEFAULT_REPOSITORY
    if "testpypi" in index_servers:
        config["testpypi"]["repository"] = TEST_REPOSITORY

    # optional configuration values for individual repositories
    for repository in index_servers:
        for key in [
            "username",
            "repository",
            "password",
            "ca_cert",
            "client_cert",
        ]:
            if parser.has_option(repository, key):
                config[repository][key] = parser.get(repository, key)

    # convert the defaultdict to a regular dict at this point
    # to prevent surprising behavior later on
    return dict(config)


def _validate_repository_url(repository_url: str) -> None:
    """Validate the given url for allowed schemes and components."""
    # Allowed schemes are http and https, based on whether the repository
    # supports TLS or not, and scheme and host must be present in the URL
    validator = (
        rfc3986.validators.Validator()
        .allow_schemes("http", "https")
        .require_presence_of("scheme", "host")
    )
    try:
        validator.validate(rfc3986.uri_reference(repository_url))
    except rfc3986.exceptions.RFC3986Exception as exc:
        raise exceptions.UnreachableRepositoryURLDetected(
            f"Invalid repository URL: {exc.args[0]}."
        )


def get_repository_from_config(
    config_file: str, repository: str, repository_url: Optional[str] = None
) -> RepositoryConfig:
    # Get our config from, if provided, command-line values for the
    # repository name and URL, or the .pypirc file

    if repository_url:
        _validate_repository_url(repository_url)
        # prefer CLI `repository_url` over `repository` or .pypirc
        return {
            "repository": repository_url,
            "username": None,
            "password": None,
        }
    try:
        return get_config(config_file)[repository]
    except KeyError:
        msg = (
            "Missing '{repo}' section from the configuration file\n"
            "or not a complete URL in --repository-url.\n"
            "Maybe you have an out-dated '{cfg}' format?\n"
            "more info: "
            "https://packaging.python.org/specifications/pypirc/\n"
        ).format(repo=repository, cfg=config_file)
        raise exceptions.InvalidConfiguration(msg)


_HOSTNAMES = {
    "pypi.python.org",
    "testpypi.python.org",
    "upload.pypi.org",
    "test.pypi.org",
}


def normalize_repository_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.netloc in _HOSTNAMES:
        return urlunparse(("https",) + parsed[1:])
    return urlunparse(parsed)


def get_file_size(filename: str) -> str:
    """Return the size of a file in KB, or MB if >= 1024 KB."""
    file_size = os.path.getsize(filename) / 1024
    size_unit = "KB"

    if file_size > 1024:
        file_size = file_size / 1024
        size_unit = "MB"

    return f"{file_size:.1f} {size_unit}"


def check_status_code(response: requests.Response, verbose: bool) -> None:
    """Generate a helpful message based on the response from the repository.

    Raise a custom exception for recognized errors. Otherwise, print the
    response content (based on the verbose option) before re-raising the
    HTTPError.
    """
    if response.status_code == 410 and "pypi.python.org" in response.url:
        raise exceptions.UploadToDeprecatedPyPIDetected(
            f"It appears you're uploading to pypi.python.org (or "
            f"testpypi.python.org). You've received a 410 error response. "
            f"Uploading to those sites is deprecated. The new sites are "
            f"pypi.org and test.pypi.org. Try using {DEFAULT_REPOSITORY} (or "
            f"{TEST_REPOSITORY}) to upload your packages instead. These are "
            f"the default URLs for Twine now. More at "
            f"https://packaging.python.org/guides/migrating-to-pypi-org/."
        )
    elif response.status_code == 405 and "pypi.org" in response.url:
        raise exceptions.InvalidPyPIUploadURL(
            f"It appears you're trying to upload to pypi.org but have an "
            f"invalid URL. You probably want one of these two URLs: "
            f"{DEFAULT_REPOSITORY} or {TEST_REPOSITORY}. Check your "
            f"--repository-url value."
        )

    try:
        response.raise_for_status()
    except requests.HTTPError as err:
        if response.text:
            if verbose:
                print("Content received from server:\n{}".format(response.text))
            else:
                print("NOTE: Try --verbose to see response content.")
        raise err


def get_userpass_value(
    cli_value: Optional[str],
    config: RepositoryConfig,
    key: str,
    prompt_strategy: Optional[Callable[[], str]] = None,
) -> Optional[str]:
    """Get the username / password from config.

    Uses the following rules:

    1. If it is specified on the cli (`cli_value`), use that.
    2. If `config[key]` is specified, use that.
    3. If `prompt_strategy`, prompt using `prompt_strategy`.
    4. Otherwise return None

    :param cli_value: The value supplied from the command line or `None`.
    :type cli_value: unicode or `None`
    :param config: Config dictionary
    :type config: dict
    :param key: Key to find the config value.
    :type key: unicode
    :prompt_strategy: Argumentless function to return fallback value.
    :type prompt_strategy: function
    :returns: The value for the username / password
    :rtype: unicode
    """
    if cli_value is not None:
        return cli_value
    elif config.get(key) is not None:
        return config[key]
    elif prompt_strategy:
        return prompt_strategy()
    else:
        return None


get_cacert = functools.partial(get_userpass_value, key="ca_cert")
get_clientcert = functools.partial(get_userpass_value, key="client_cert")


class EnvironmentDefault(argparse.Action):
    """Get values from environment variable."""

    def __init__(
        self,
        env: str,
        required: bool = True,
        default: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        default = os.environ.get(env, default)
        self.env = env
        if default:
            required = False
        super().__init__(default=default, required=required, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None],
        option_string: Optional[str] = None,
    ) -> None:
        setattr(namespace, self.dest, values)


class EnvironmentFlag(argparse.Action):
    """Set boolean flag from environment variable."""

    def __init__(self, env: str, **kwargs: Any) -> None:
        default = self.bool_from_env(os.environ.get(env))
        self.env = env
        super().__init__(default=default, nargs=0, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None],
        option_string: Optional[str] = None,
    ) -> None:
        setattr(namespace, self.dest, True)

    @staticmethod
    def bool_from_env(val: Optional[str]) -> bool:
        """Allow '0' and 'false' and 'no' to be False."""
        falsey = {"0", "false", "no"}
        return bool(val and val.lower() not in falsey)
