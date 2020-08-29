import functools
import getpass
import warnings
from typing import Callable
from typing import Optional
from typing import Type
from typing import cast

import keyring

from twine import exceptions
from twine import utils


class CredentialInput:
    def __init__(
        self, username: Optional[str] = None, password: Optional[str] = None
    ) -> None:
        self.username = username
        self.password = password


class Resolver:
    def __init__(self, config: utils.RepositoryConfig, input: CredentialInput) -> None:
        self.config = config
        self.input = input

    @classmethod
    def choose(cls, interactive: bool) -> Type["Resolver"]:
        return cls if interactive else Private

    @property  # type: ignore  # https://github.com/python/mypy/issues/1362
    @functools.lru_cache()
    def username(self) -> Optional[str]:
        return utils.get_userpass_value(
            self.input.username,
            self.config,
            key="username",
            prompt_strategy=self.username_from_keyring_or_prompt,
        )

    @property  # type: ignore  # https://github.com/python/mypy/issues/1362
    @functools.lru_cache()
    def password(self) -> Optional[str]:
        return utils.get_userpass_value(
            self.input.password,
            self.config,
            key="password",
            prompt_strategy=self.password_from_keyring_or_prompt,
        )

    @property
    def system(self) -> Optional[str]:
        return self.config["repository"]

    def get_username_from_keyring(self) -> Optional[str]:
        try:
            creds = keyring.get_credential(self.system, None)
            if creds:
                return cast(str, creds.username)
        except AttributeError:
            # To support keyring prior to 15.2
            pass
        except Exception as exc:
            warnings.warn(str(exc))
        return None

    def get_password_from_keyring(self) -> Optional[str]:
        try:
            return cast(str, keyring.get_password(self.system, self.username))
        except Exception as exc:
            warnings.warn(str(exc))
        return None

    def username_from_keyring_or_prompt(self) -> str:
        return self.get_username_from_keyring() or self.prompt("username", input)

    def password_from_keyring_or_prompt(self) -> str:
        return self.get_password_from_keyring() or self.prompt(
            "password", getpass.getpass
        )

    def prompt(self, what: str, how: Callable[..., str]) -> str:
        return how(f"Enter your {what}: ")


class Private(Resolver):
    def prompt(self, what: str, how: Optional[Callable[..., str]] = None) -> str:
        raise exceptions.NonInteractive(f"Credential not found for {what}.")
