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

OpenSSL has a CSPRNG that it seeds when starting up. Unfortunately, its state
is replicated when the process is forked and child processes can deliver
similar or identical random values. OpenSSL has landed a patch to mitigate this
issue, but this project can't rely on users having recent versions.

To work around this cryptography uses a custom OpenSSL engine that replaces the
standard random source with one that fetches entropy from ``/dev/urandom`` (or
CryptGenRandom on Windows). This engine is **active** by default when importing
the OpenSSL backend. It is added to the engine list but not activated if you
only import the binding.

.. _`OpenSSL`: https://www.openssl.org/
