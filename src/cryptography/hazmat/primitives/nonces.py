# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from os import urandom
from typing import ClassVar, Optional


class Nonce(bytes):
    """
    Each unique nonce value is an instantiated
        object of this bytes subclass.
    """

    @classmethod
    def from_bytes(cls, nonce: bytes) -> "Nonce":
        """
        Load a unique nonce value.

        :param nonce: nonce bytes.
        :rtype: Nonce.
        """
        if not isinstance(nonce, bytes):
            raise TypeError("nonce must be bytes")

        return cls(nonce)

    @classmethod
    def random(cls, size: int) -> "Nonce":
        """
        Get random Nonce from a size.

        :param size: size of the nonce.
        :rtype: Nonce.
        """
        if not isinstance(size, int):
            raise TypeError("nonce size must be int")

        return cls(urandom(size))


class Nonces:
    """
    Nonces generator based on:
        - A given size.
        - A counter size.
        - An optional seed.
        - An optional byte order for the counter.
        - An optional trailing position argument for the counter.

    All nonces generated will use a counter.

    :cvar _DEFAULT_INCREMENT: default increment value for counter.
    :cvar _ORDER_OPTIONS: byte order options.
    """

    _DEFAULT_INCREMENT: ClassVar[int] = 1
    _ORDER_OPTIONS: ClassVar[list] = ["big", "little"]

    def __init__(
        self,
        size: int,
        counter_size: int,
        seed: Optional[bytes] = None,
        order: Optional[str] = _ORDER_OPTIONS[0],
        trailing_counter: Optional[bool] = True,
    ):
        """
        :param size: size of the full nonce (nonce + counter).
        :param counter_size: size of the counter.
        :param seed: seed to use for the non-counter portion of the nonce.
        :param order: byte order for the counter.
            "big" means big endian for the counter.
            "little" mean little endian for the counter.
        :param trailing_counter: trailing counter or not.
            True means nonce + counter
            False means counter + nonce
        """
        if not isinstance(size, int):
            raise TypeError("nonce size must be int")
        if size < 1:
            raise ValueError("nonce size cannot be smaller than 1 byte")
        if not isinstance(counter_size, int):
            raise TypeError("counter size must be int")
        if counter_size > size:
            raise ValueError("counter size cannot be bigger than nonce size")
        if seed is not None:
            if not isinstance(seed, bytes):
                raise TypeError("seed must be bytes")
        if not isinstance(order, str):
            raise TypeError("order must be str")
        if order not in self._ORDER_OPTIONS:
            raise ValueError(
                "order must be '{}' or '{}'".format(*self._ORDER_OPTIONS)
            )
        if not isinstance(trailing_counter, bool):
            raise TypeError("trailing_counter must be bool")

        self._size = size
        self._counter_size = counter_size
        self._seed_size = self._size - self._counter_size
        if seed is None:
            self._seed_bytes = urandom(self._seed_size)
        else:
            if len(seed) != self._seed_size:
                raise ValueError(f"seed must be {self._seed_size} bytes")
            self._seed_bytes = seed
        self._order = order
        self._trailing_counter = trailing_counter
        self._max_counter = 2 ** (self._counter_size * 8) - 1
        self._counter = 0
        self._counter_bytes = self.counter_to_bytes()
        self._nonce = self._build_nonce()
        self._increment = self._DEFAULT_INCREMENT

    def update(self) -> Nonce:
        """
        Update nonce value incrementing counter.

        :raises: OverflowError in case of counter overflow.
        :rtype: Nonce.
        """
        if self._counter + self._increment <= self._max_counter:
            self._counter += self._increment
            self._counter_bytes = self.counter_to_bytes()
            self._nonce = self._build_nonce()
        else:
            raise OverflowError("counter overflow")

        return self._nonce

    def _build_nonce(self) -> Nonce:
        """
        Get Nonce object

        :rtype: Nonce.
        """
        if self._trailing_counter is True:
            return Nonce.from_bytes(self._seed_bytes + self._counter_bytes)
        else:
            return Nonce.from_bytes(self._counter_bytes + self._seed_bytes)

    def set_counter(self, counter: int) -> Nonce:
        """
        Set counter to new value.

        :param counter: counter value.
        :raises: ValueError or AssertionError.
        :rtype: Nonce.
        """
        if not isinstance(counter, int):
            raise TypeError("must be integer")
        if not counter <= self._max_counter:
            raise ValueError(f"must be smaller than {self._max_counter}")
        if counter < self._counter:
            raise AssertionError(
                "counter must be greater than current counter"
            )
        self._counter = counter
        self._counter_bytes = self.counter_to_bytes()
        self._nonce = self._build_nonce()

        return self._nonce

    def counter_to_bytes(self):
        """
        Get counter in bytes.

        :rtype: bytes.
        """
        return self._counter.to_bytes(
            length=self._counter_size,
            byteorder=self._order,  # type: ignore[arg-type]
        )

    def __bytes__(self):
        """
        Return current nonce bytes.

        :rtype: :class:`Nonce`.
        """
        return self._nonce

    @property
    def counter_bytes(self) -> bytes:
        """
        Return current nonce counter bytes.

        :rtype: bytes.
        """
        return self._counter_bytes

    @property
    def seed_bytes(self) -> bytes:
        """
        Return current nonce bytes without counter.

        :rtype: bytes.
        """
        return self._seed_bytes

    @property
    def nonce(self) -> bytes:
        """
        Return current nonce.

        :rtype: Nonce.
        """
        return self._nonce

    @property
    def increment(self) -> int:
        """
        Return current increment value.

        :rtype: int.
        """
        return self._increment

    @increment.setter
    def increment(self, value: int):
        """
        Setter for increment.

        :param value: increment value.
        """
        if not isinstance(value, int):
            raise TypeError("must be integer")
        if value <= 0:
            raise ValueError("must be greater than 0")
        max_increment = self._max_counter - self._counter
        if value > max_increment:
            raise ValueError(f"must be smaller than {max_increment}")
        self._increment = value

    @property
    def order(self) -> str:
        """
        Return current counter byte order.

        :rtype: str.
        """
        return self._order

    @property
    def counter(self) -> int:
        """
        Return current counter value.

        :rtype: int.
        """
        return self._counter

    @property
    def max_counter(self) -> int:
        """
        Return max counter value.

        :rtype: int.
        """
        return self._max_counter

    @property
    def size(self) -> int:
        """
        Return full nonce size.

        :rtype: int.
        """
        return self._size

    @property
    def counter_size(self) -> int:
        """
        Return counter size.

        :rtype: int.
        """
        return self._counter_size

    @property
    def seed_size(self) -> int:
        """
        Return nonce size without counter.

        :rtype: int.
        """
        return self._seed_size
