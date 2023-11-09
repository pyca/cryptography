# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import datetime
import typing

from cryptography.hazmat.bindings._rust import x509 as rust_x509
from cryptography.x509.general_name import DNSName, IPAddress

__all__ = ["Store", "Subject", "ServerVerifier", "PolicyBuilder"]

Store = rust_x509.Store

Subject = typing.Union[DNSName, IPAddress]

ServerVerifier = rust_x509.ServerVerifier


class PolicyBuilder:
    def __init__(
        self,
        *,
        time: datetime.datetime | None = None,
        store: Store | None = None,
        max_chain_depth: int | None = None,
    ):
        self._time = time
        self._store = store
        self._max_chain_depth = max_chain_depth

    def time(self, new_time: datetime.datetime) -> PolicyBuilder:
        """
        Sets the validation time.
        """
        if self._time is not None:
            raise ValueError("The validation time may only be set once.")

        return PolicyBuilder(
            time=new_time,
            store=self._store,
            max_chain_depth=self._max_chain_depth,
        )

    def store(self, new_store: Store) -> PolicyBuilder:
        """
        Sets the trust store.
        """

        if self._store is not None:
            raise ValueError("The trust store may only be set once.")

        return PolicyBuilder(
            time=self._time,
            store=new_store,
            max_chain_depth=self._max_chain_depth,
        )

    def max_chain_depth(self, new_max_chain_depth: int) -> PolicyBuilder:
        """
        Sets the maximum chain depth.
        """

        if self._max_chain_depth is not None:
            raise ValueError("The maximum chain depth may only be set once.")

        return PolicyBuilder(
            time=self._time,
            store=self._store,
            max_chain_depth=new_max_chain_depth,
        )

    def max_chain_depth(self, new_max_chain_depth: int) -> PolicyBuilder:
        """
        Sets the maximum chain depth.
        """

        if self._max_chain_depth is not None:
            raise ValueError("The maximum chain depth may only be set once.")

        return PolicyBuilder(
            time=self._time,
            store=self._store,
            max_chain_depth=new_max_chain_depth,
        )

    def build_server_verifier(self, subject: Subject) -> ServerVerifier:
        """
        Builds a verifier for verifying server certificates.
        """

        if self._store is None:
            raise ValueError("A server verifier must have a trust store")

        return rust_x509.create_server_verifier(
            subject,
            self._store,
            self._time,
            self._max_chain_depth,
        )
