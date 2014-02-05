.. hazmat::

OpenSSL Backend
===============

The `OpenSSL`_ C library.

.. data:: cryptography.hazmat.backends.openssl.backend

    This is the exposed API for the OpenSSL backend.

    It implements the following interfaces:

    * :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.HashBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.PBKDF2HMACBackend`

    It also exposes the following:

    .. attribute:: name

        The string name of this backend: ``"openssl"``

    .. method:: activate_osrandom_engine()

        Activates the OS random engine. This will effectively disable OpenSSL's
        default CSPRNG.

    .. method:: activate_builtin_random()

        This will activate the default OpenSSL CSPRNG.

OS Random Engine
----------------

OpenSSL uses a user-space CSPRNG that is seeded from system random (
``/dev/urandom`` or ``CryptGenRandom``). This CSPRNG is not reseeded
automatically when a process calls ``fork()``. This can result in situations
where two different processes can return similar or identical keys and
compromise the security of the system.

The approach this project has chosen to mitigate this vulnerability is to
include an engine that replaces the OpenSSL default CSPRNG with one that sources
its entropy from ``/dev/urandom`` on UNIX-like operating systems and uses
``CryptGenRandom`` on Windows. This method of pulling from the system pool
allows us to avoid potential issues with `initializing the RNG`_ as well as
protecting us from the ``fork()`` weakness.

This engine is **active** by default when importing the OpenSSL backend. When
active this engine will be used to generate all the random data OpenSSL
requests.

When importing only the binding it is added to the engine list but
**not activated**.


OS Random Sources
-----------------

On OS X and FreeBSD ``/dev/urandom`` is an alias for ``/dev/random`` and
utilizes the `Yarrow`_ algorithm.

On Windows ``CryptGenRandom`` is backed by `Fortuna`_.

Linux uses its own PRNG design. ``/dev/urandom`` is a non-blocking source seeded
from the same pool as ``/dev/random``.


.. _`OpenSSL`: https://www.openssl.org/
.. _`initializing the RNG`: http://en.wikipedia.org/wiki/OpenSSL#Vulnerability_in_the_Debian_implementation
.. _`Yarrow`: http://en.wikipedia.org/wiki/Yarrow_algorithm
.. _`Fortuna`: http://en.wikipedia.org/wiki/Fortuna_(PRNG)
