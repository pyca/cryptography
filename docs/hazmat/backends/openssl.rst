.. hazmat::

OpenSSL backend
===============

The `OpenSSL`_ C library. Cryptography supports OpenSSL version 1.0.1 and
greater.

.. data:: cryptography.hazmat.backends.openssl.backend

    This is the exposed API for the OpenSSL backend.

    It implements the following interfaces:

    * :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.CMACBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.DERSerializationBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.DHBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.DSABackend`
    * :class:`~cryptography.hazmat.backends.interfaces.EllipticCurveBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.HashBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.PBKDF2HMACBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.RSABackend`
    * :class:`~cryptography.hazmat.backends.interfaces.PEMSerializationBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.X509Backend`

    It also implements the following interface for OpenSSL versions ``1.1.0``
    and above.

    * :class:`~cryptography.hazmat.backends.interfaces.ScryptBackend`

    It also exposes the following:

    .. attribute:: name

        The string name of this backend: ``"openssl"``

    .. method:: openssl_version_text()

        :return text: The friendly string name of the loaded OpenSSL library.
            This is not necessarily the same version as it was compiled against.

    .. method:: openssl_version_number()

        .. versionadded:: 1.8

        :return int: The integer version of the loaded OpenSSL library. This is
            defined in ``opensslv.h`` as ``OPENSSL_VERSION_NUMBER`` and is
            typically shown in hexadecimal (e.g. ``0x1010003f``). This is
            not necessarily the same version as it was compiled against.

    .. method:: activate_osrandom_engine()

        Activates the OS random engine. This will effectively disable OpenSSL's
        default CSPRNG.

    .. method:: osrandom_engine_implementation()

        .. versionadded:: 1.7

        Returns the implementation of OS random engine.

    .. method:: activate_builtin_random()

        This will activate the default OpenSSL CSPRNG.

OS random engine
----------------

By default OpenSSL uses a user-space CSPRNG that is seeded from system random (
``/dev/urandom`` or ``CryptGenRandom``). This CSPRNG is not reseeded
automatically when a process calls ``fork()``. This can result in situations
where two different processes can return similar or identical keys and
compromise the security of the system.

The approach this project has chosen to mitigate this vulnerability is to
include an engine that replaces the OpenSSL default CSPRNG with one that
sources its entropy from ``/dev/urandom`` on UNIX-like operating systems and
uses ``CryptGenRandom`` on Windows. This method of pulling from the system pool
allows us to avoid potential issues with `initializing the RNG`_ as well as
protecting us from the ``fork()`` weakness.

This engine is **active** by default when importing the OpenSSL backend. When
active this engine will be used to generate all the random data OpenSSL
requests.

When importing only the binding it is added to the engine list but
**not activated**.


OS random sources
-----------------

On macOS and FreeBSD ``/dev/urandom`` is an alias for ``/dev/random``. The
implementation on macOS uses the `Yarrow`_ algorithm. FreeBSD uses the
`Fortuna`_ algorithm.

On Windows the implementation of ``CryptGenRandom`` depends on which version of
the operation system you are using. See the `Microsoft documentation`_ for more
details.

Linux uses its own PRNG design. ``/dev/urandom`` is a non-blocking source
seeded from the same pool as ``/dev/random``.

+------------------------------------------+------------------------------+
| Windows                                  | ``CryptGenRandom()``         |
+------------------------------------------+------------------------------+
| Linux >= 3.4.17 with working             | ``getrandom(GRND_NONBLOCK)`` |
| ``SYS_getrandom`` syscall                |                              |
+------------------------------------------+------------------------------+
| OpenBSD >= 5.6                           | ``getentropy()``             |
+------------------------------------------+------------------------------+
| BSD family (including macOS 10.12+) with | ``getentropy()``             |
| ``SYS_getentropy`` in ``sys/syscall.h``  |                              |
+------------------------------------------+------------------------------+
| fallback                                 | ``/dev/urandom`` with        |
|                                          | cached file descriptor       |
+------------------------------------------+------------------------------+


.. _`OpenSSL`: https://www.openssl.org/
.. _`initializing the RNG`: https://en.wikipedia.org/wiki/OpenSSL#Predictable_private_keys_.28Debian-specific.29
.. _`Fortuna`: https://en.wikipedia.org/wiki/Fortuna_(PRNG)
.. _`Yarrow`: https://en.wikipedia.org/wiki/Yarrow_algorithm
.. _`Microsoft documentation`: https://msdn.microsoft.com/en-us/library/windows/desktop/aa379942(v=vs.85).aspx
