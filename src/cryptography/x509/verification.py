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
        subject: Subject | None = None,
        time: datetime.datetime | None = None,
    ):
        self._subject = subject
        self._time = time

    @classmethod
    def webpki(cls) -> PolicyBuilder:
        return PolicyBuilder(time=datetime.datetime.now())

    def subject(self, new_subject: Subject) -> PolicyBuilder:
        """
        Sets the expected certificate subject.
        """
        return PolicyBuilder(
            subject=new_subject,
            time=self._time,
        )

    def time(self, new_time: datetime.datetime) -> PolicyBuilder:
        """
        Sets the validation time.
        """
        return PolicyBuilder(
            subject=self._subject,
            time=new_time,
        )

    def build(self) -> typing.NoReturn:
        """
        Construct a `Policy` from this `PolicyBuilder`.
        """

        raise NotImplementedError
