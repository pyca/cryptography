Random number generation
========================

When generating random data for use in cryptographic operations, such as an
initialization vector for encryption in
:class:`~cryptography.hazmat.primitives.ciphers.modes.CBC` mode, you do not
want to use the standard :mod:`random` module APIs. This is because they do not
provide a cryptographically secure random number generator, which can result in
major security issues depending on the algorithms in use.

Therefore, it is our recommendation to `always use your operating system's
provided random number generator`_, which is available as :func:`os.urandom`.
For example, if you need 16 bytes of random data for an initialization vector,
you can obtain them with:

.. doctest::

    >>> import os
    >>> iv = os.urandom(16)

This will use ``/dev/urandom`` on UNIX platforms, and ``CryptGenRandom`` on
Windows.

If you need your random number as an integer (for example, for
:meth:`~cryptography.x509.CertificateBuilder.serial_number`), you can use
``int.from_bytes`` to convert the result of ``os.urandom``:

.. code-block:: pycon

    >>> serial = int.from_bytes(os.urandom(20), byteorder="big")

In addition, the `Python standard library`_ includes the ``secrets`` module,
which can be used for generating cryptographically secure random numbers, with
specific helpers for text-based formats.

.. _`always use your operating system's provided random number generator`: https://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/
.. _`Python standard library`: https://docs.python.org/3/library/secrets.html
