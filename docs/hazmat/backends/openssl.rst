.. hazmat::

OpenSSL Backend
===============

The `OpenSSL`_ C library.

.. data:: cryptography.hazmat.backends.openssl.backend

    This is the exposed API for the OpenSSL backend.

    .. attribute:: name

        The string name of this backend: ``"openssl"``

    .. method:: register_osrandom_engine()

        Registers the OS random engine as default. This will effectively
        disable OpenSSL's default CSPRNG.

    .. method:: unregister_osrandom_engine()

        Unregisters the OS random engine if it is default. This will restore
        the default OpenSSL CSPRNG. If the OS random engine is not the default
        engine (e.g. if another engine is set as default) nothing will be
        changed.

OS Random Engine
----------------

OpenSSL uses a userspace CSPRNG that is seeded from system random (
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

This engine is **active** by default when importing the OpenSSL backend. It is
added to the engine list but **not activated** if you only import the binding.
If you wish to deactivate it call ``unregister_osrandom_engine()`` on the
backend object.

OS Random Sources
-----------------

On OS X and FreeBSD ``/dev/urandom`` is an alias for ``/dev/random`` and
utilizes the `Yarrow`_ algorithm.

On Windows ``CryptGenRandom`` is backed by `Fortuna`_.

Linux uses its own PRNG design. ``/dev/urandom`` is a non-blocking source seeded
from the ``/dev/random`` pool.


.. _`OpenSSL`: https://www.openssl.org/
.. _`initializing the RNG`: http://en.wikipedia.org/wiki/OpenSSL#Vulnerability_in_the_Debian_implementation
.. _`Yarrow`: http://en.wikipedia.org/wiki/Yarrow_algorithm
.. _`Fortuna`: http://en.wikipedia.org/wiki/Fortuna_(PRNG)
