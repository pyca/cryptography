Installation
============

You can install ``cryptography`` with ``pip``:

.. code-block:: console

    $ pip install cryptography

Supported platforms
-------------------

Currently we test ``cryptography`` on Python 2.6, 2.7, 3.2, 3.3, 3.4 and PyPy
on these operating systems.

* x86-64 CentOS 7.x, 6.4 and CentOS 5.x
* x86-64 FreeBSD 9.2 and FreeBSD 10
* OS X 10.10 Yosemite, 10.9 Mavericks, 10.8 Mountain Lion, and 10.7 Lion
* x86-64 Ubuntu 12.04 LTS
* x86-64 Debian Wheezy (7.x) and Jessie (8.x)
* 32-bit Python on 64-bit Windows Server 2008
* 64-bit Python on 64-bit Windows Server 2012

We test compiling with ``clang`` as well as ``gcc`` and use the following
OpenSSL releases:

* ``OpenSSL 0.9.8e-fips-rhel5`` (``RHEL/CentOS 5``)
* ``OpenSSL 0.9.8k``
* ``OpenSSL 0.9.8za``
* ``OpenSSL 1.0.0-fips`` (``RHEL/CentOS 6.4``)
* ``OpenSSL 1.0.1``
* ``OpenSSL 1.0.1e-fips`` (``RHEL/CentOS 7``)
* ``OpenSSL 1.0.1e-freebsd``
* ``OpenSSL 1.0.1-latest`` (The most recent 1.0.1 release)
* ``OpenSSL 1.0.2``

On Windows
----------

The wheel package on Windows is a statically linked build (as of 0.5) so all
dependencies are included. Just run

.. code-block:: console

    $ pip install cryptography

If you prefer to compile it yourself you'll need to have OpenSSL installed.
There are `pre-compiled binaries`_ available. If your installation is in an
unusual location set the ``LIB`` and ``INCLUDE`` environment variables to
include the corresponding locations.For example:

.. code-block:: console

    C:\> \path\to\vcvarsall.bat x86_amd64
    C:\> set LIB=C:\OpenSSL\lib\VC\static;C:\OpenSSL\lib;%LIB%
    C:\> set INCLUDE=C:\OpenSSL\include;%INCLUDE%
    C:\> pip install cryptography

You can also choose to build statically or dynamically using the
``PYCA_WINDOWS_LINK_TYPE`` variable. Allowed values are ``static`` (default)
and ``dynamic``.

.. code-block:: console

    C:\> \path\to\vcvarsall.bat x86_amd64
    C:\> set LIB=C:\OpenSSL\lib\VC\static;C:\OpenSSL\lib;%LIB%
    C:\> set INCLUDE=C:\OpenSSL\include;%INCLUDE%
    C:\> set PYCA_WINDOWS_LINK_TYPE=dynamic
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
``ARCHFLAGS``, ``LDFLAGS``, and ``CFLAGS``. OpenSSL can be installed via
`Homebrew`_ or `MacPorts`_:

`Homebrew`_

.. code-block:: console

    $ brew install openssl
    $ env ARCHFLAGS="-arch x86_64" LDFLAGS="-L/usr/local/opt/openssl/lib" CFLAGS="-I/usr/local/opt/openssl/include" pip install cryptography

or `MacPorts`_:

.. code-block:: console

    $ sudo port install openssl
    $ env ARCHFLAGS="-arch x86_64" LDFLAGS="-L/opt/local/lib" CFLAGS="-I/opt/local/include" pip install cryptography

Building cryptography with conda
--------------------------------

Because of a `bug in conda`_, attempting to install cryptography out of the box
will result in an error. This can be resolved by setting the library path
environment variable for your platform.

On OS X:

.. code-block:: console

    $ env DYLD_LIBRARY_PATH="$HOME/anaconda/lib" pip install cryptography

and on Linux:

.. code-block:: console

    $ env LD_LIBRARY_PATH="$HOME/anaconda/lib" pip install cryptography

You will need to set this variable every time you start Python. For more
information, consult `Greg Wilson's blog post`_ on the subject.


.. _`Homebrew`: http://brew.sh
.. _`MacPorts`: http://www.macports.org
.. _`pre-compiled binaries`: https://www.openssl.org/related/binaries.html
.. _`bug in conda`: https://github.com/conda/conda-recipes/issues/110
.. _`Greg Wilson's blog post`: http://software-carpentry.org/blog/2014/04/mr-biczo-was-right.html
