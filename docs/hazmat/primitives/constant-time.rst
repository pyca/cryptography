.. hazmat::

Constant time functions
=======================

.. currentmodule:: cryptography.hazmat.primitives.constant_time

In order for cryptographic operations to not leak information through timing
side channels, constant time operations need to be used.

One should use these functions whenever you are comparing a secret to
something received. This includes things like HMAC signatures as described by
a `timing attack on KeyCzar`_.


.. function:: bytes_eq(a, b)

    Compare ``a`` and ``b`` to one another in constant time if they are of the
    same length.

    .. doctest::

        >>> from cryptography.hazmat.primitives import constant_time
        >>> constant_time.bytes_eq(b"foo", b"foo")
        True
        >>> constant_time.bytes_eq(b"foo", b"bar")
        False

    :param a bytes: The left-hand side.
    :param b bytes: The right-hand side.
    :returns boolean: True if ``a`` has the same bytes as ``b``.


.. _`timing attack on KeyCzar`: http://rdist.root.org/2009/05/28/timing-attack-in-google-keyczar-library/
