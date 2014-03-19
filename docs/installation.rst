Installation
============

You can install ``cryptography`` with ``pip``:

.. code-block:: console

    $ pip install cryptography

Supported platforms
-------------------

Currently we test ``cryptography`` on Python 2.6, 2.7, 3.2, 3.3 and PyPy on
these operating systems.

* x86-64 CentOS 6.4 and CentOS 5
* x86-64 FreeBSD 9.2 and FreeBSD 10
* OS X 10.9 and OS X 10.8
* x86-64 Ubuntu 12.04 LTS
* 32-bit Python on 64-bit Windows Server 2008

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

Building cryptography on Linux
------------------------------

``cryptography`` should build very easily on Linux provided you have a C
compiler, headers for Python (if you're not using ``pypy``), and headers for
the OpenSSL and ``libffi`` libraries available on your system.

For Debian and Ubuntu, the following command will ensure that the required
dependencies are installed:

.. code-block:: console

    $ sudo apt-get install build-essential libssl-dev libffi-dev python-dev

For Fedora and RHEL-derivatives, the following command will ensure that the
required dependencies are installed:

.. code-block:: console

    $ sudo yum install gcc libffi-devel python-devel openssl-devel

You should now be able to build and install cryptography with the usual

.. code-block:: console

    $ pip install cryptography

Using your own OpenSSL on Linux
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
``ARCHFLAGS``, ``LDFLAGS``, and ``CFLAGS``. OpenSSL can be installed via `Homebrew`_:

.. code-block:: console

    $ brew install openssl

or `MacPorts`_:

.. code-block:: console

    $ sudo port install openssl


Then install cryptography linking against the brewed version:

on `Homebrew`_:

.. code-block:: console

    $ env ARCHFLAGS="-arch x86_64" LDFLAGS="-L/usr/local/opt/openssl/lib" CFLAGS="-I/usr/local/opt/openssl/include" pip install cryptography

on `MacPorts`_:

.. code-block:: console

    $ env ARCHFLAGS="-arch x86_64" LDFLAGS="-L/opt/local/lib" CFLAGS="-I/opt/local/include" pip install cryptography

.. _`Homebrew`: http://brew.sh
.. _`MacPorts`: http://www.macports.org
.. _`pre-compiled binaries`: https://www.openssl.org/related/binaries.html
