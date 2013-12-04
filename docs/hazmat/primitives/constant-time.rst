.. hazmat::

Constant time functions
=======================

.. currentmodule:: cryptography.hazmat.primitives.constant_time

In order for cryptographic operations to not leak information through timing
side channels, constant time operations need to be made available.

.. function:: bytes_eq(a, b)

    Compare ``a`` and ``b`` to one another in constant time.

    .. doctest::

        >>> from cryptography.hazmat.primitives import constant_time
        >>> constant_time.bytes_eq(b"foo", b"foo")
        True
        >>> constant_time.bytes_eq(b"foo", b"bar")
        False

    :param a: ``bytes``.
    :param b: ``bytes``.
