Use of OpenSSL
==============

``cryptography`` depends on the `OpenSSL`_ C library for all cryptographic
operation. OpenSSL is the de facto standard for cryptographic libraries and
provides high performance along with various certifications that may be
relevant to developers.

A list of supported versions can be found in our :doc:`/installation`
documentation.

In general the backend should be considered an internal implementation detail
of the project, but there are some public methods available for more advanced
control.

.. data:: cryptography.hazmat.backends.openssl.backend

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

.. _legacy-provider:

Legacy provider in OpenSSL 3.x
------------------------------

.. versionadded:: 39.0.0

Users can set ``CRYPTOGRAPHY_OPENSSL_NO_LEGACY`` environment variable to
disable the legacy provider in OpenSSL 3.x. This will disable legacy
cryptographic algorithms, including ``Blowfish``, ``CAST5``, ``SEED``,
``ARC4``, and ``RC2`` (which is used by some encrypted serialization formats).

OS random engine
----------------

.. note::

    As of OpenSSL 1.1.1d its CSPRNG is fork-safe by default.
    ``cryptography`` does not compile or load the custom engine on
    >= 1.1.1d.

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
| Linux >= 3.17 with working               | ``getrandom()``              |
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
.. _`Microsoft documentation`: https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/nf-wincrypt-cryptgenrandom
