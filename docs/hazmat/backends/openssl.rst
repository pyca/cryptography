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


Using your own OpenSSL on Linux
-------------------------------

Python links to OpenSSL for its own purposes and this can sometimes cause
problems when you wish to use a different version of OpenSSL with cryptography.
If you want to use cryptography with your own build of OpenSSL you will need to
make sure that the build is configured correctly so that your version of
OpenSSL doesn't conflict with Python's.

The options you need to add allow the linker to identify every symbol correctly
even when multiple versions of the library are linked into the same program. If
you are using your distribution's source packages these will probably be
patched in for you already, otherwise you'll need to use options something like
this when configuring OpenSSL::

    ./config -Wl,--version-script=openssl.ld -Wl,-Bsymbolic-functions -fPIC shared

You'll also need to generate your own ``openssl.ld`` file. For example::

    OPENSSL_1.0.1F_CUSTOM {
        global:
            *;
    };

You should replace the version string on the first line as appropriate for your
build.

.. _`OpenSSL`: https://www.openssl.org/
