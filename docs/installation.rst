Installation
============

You can install ``cryptography`` with ``pip``:

.. code-block:: console

    $ pip install cryptography

On Windows
----------

If you're on Windows you'll need to make sure you have OpenSSL installed.
There are `pre-compiled binaries`_ available. If your installation is in
an unusual location set the ``LIB`` and ``INCLUDE`` environment variables
to include the corresponding locations. For example:

.. code-block:: console

    C:\> \path\to\vcvarsall.bat x86_amd64
    C:\> set LIB=C:\OpenSSL-1.0.1f-64bit\lib;%LIB%
    C:\> set INCLUDE=C:\OpenSSL-1.0.1f-64bit\include;%INCLUDE%
    C:\> pip install cryptography

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
this when configuring OpenSSL:

.. code-block:: console

    $ ./config -Wl,--version-script=openssl.ld -Wl,-Bsymbolic-functions -fPIC shared

You'll also need to generate your own ``openssl.ld`` file. For example::

    OPENSSL_1.0.1F_CUSTOM {
        global:
            *;
    };

You should replace the version string on the first line as appropriate for your
build.

Using your own OpenSSL on OS X
------------------------------

To link cryptography against a custom version of OpenSSL you'll need to set
``ARCHFLAGS``, ``LDFLAGS``, and ``CFLAGS``. OpenSSL can be installed via
`Homebrew`_:

.. code-block:: console

    $ brew install openssl

Then install cryptography linking against the brewed version:

.. code-block:: console

    $ env ARCHFLAGS="-arch x86_64" LDFLAGS="-L/usr/local/opt/openssl/lib" CFLAGS="-I/usr/local/opt/openssl/include" pip install cryptography


.. _`Homebrew`: http://brew.sh
.. _`pre-compiled binaries`: https://www.openssl.org/related/binaries.html
