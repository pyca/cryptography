# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import datetime
import typing

from cryptography import utils
from cryptography.hazmat.bindings._rust import x509 as rust_x509
from cryptography.x509.base import Certificate
from cryptography.x509.general_name import DNSName, IPAddress

Subject = typing.Union[DNSName, IPAddress]


class Profile(utils.Enum):
    RFC5280 = 0
    WebPKI = 1


Policy = rust_x509.Policy


class PolicyBuilder:
    def __init__(
        self,
        *,
        subject: typing.Optional[Subject] = None,
        time: typing.Optional[datetime.datetime] = None,
        profile: Profile = Profile.WebPKI,
    ):
        self._subject = subject
        self._time = time
        self._profile = profile

    def subject(self, new_subject: Subject) -> PolicyBuilder:
        """
        Sets the expected certificate subject.
        """
        return PolicyBuilder(
            subject=new_subject, time=self._time, profile=self._profile
        )

    def time(self, new_time: datetime.datetime) -> PolicyBuilder:
        """
        Sets the validation time.
        """
        return PolicyBuilder(
            subject=self._subject, time=new_time, profile=self._profile
        )

    def profile(self, new_profile: Profile) -> PolicyBuilder:
        """
        Sets the underlying profile for this policy.
        """
        return PolicyBuilder(
            subject=self._subject, time=self._time, profile=new_profile
        )

    def build(self) -> Policy:
        """
        Construct a `Policy` from this `PolicyBuilder`.
        """

        return rust_x509.create_policy(
            self._profile, self._subject, self._time
        )


# NOTE: At the Python level, this is just a thin wrapper around a list
# of certificates. This is done solely for API misuse prevention reasons:
# having a dedicated type makes it harder for users to mix up
# their trusted and untrusted certificate sets.
class Store:
    def __init__(self, certs: typing.List[Certificate]):
        self._certs = certs


__all__ = [
    "Policy",
    "PolicyBuilder",
    "Profile",
    "Store",
]
