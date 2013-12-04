.. hazmat::

Subtle functions
================

.. currentmodule:: cryptography.hazmat.primitives.subtle

Some functions are needed for helping out other secure algorithms. This is a
those which require some thought to use correctly.

.. function:: constant_time_compare(a, b)

    Compare ``a`` and ``b`` to one another in constant time.

    .. doctest::

        >>> from cryptography.hazmat.primitives.subtle import constant_time_compare
        >>> constant_time_compare(b"foo", b"foo")
        True
        >>> constant_time_compare(b"foo", b"bar")
        False


    :param a: ``bytes``.
    :param b: ``bytes``.
