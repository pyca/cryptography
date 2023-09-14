# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import datetime
import typing

from cryptography.hazmat.bindings._rust import x509 as rust_x509
from cryptography.x509.general_name import DNSName, IPAddress

__all__ = ["Store", "Subject", "PolicyBuilder"]

Store = rust_x509.Store

Subject = typing.Union[DNSName, IPAddress]


class PolicyBuilder:
    def __init__(
        self,
        *,
        time: datetime.datetime | None = None,
    ):
        self._time = time

    @classmethod
    def webpki(cls) -> PolicyBuilder:
        return PolicyBuilder()

    def time(self, new_time: datetime.datetime) -> PolicyBuilder:
        """
        Sets the validation time.
        """
        if self._time is not None:
            raise ValueError("The validation time may only be set once.")

        return PolicyBuilder(
            time=new_time,
        )

    def build_server_policy(
        self, subject: Subject | None = None
    ) -> typing.NoReturn:
        """
        Construct a server validation `Policy` from this `PolicyBuilder`.
        """

        raise NotImplementedError
