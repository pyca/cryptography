Installation
============

You can install ``cryptography`` with ``pip``:

.. code-block:: console

    $ pip install cryptography

Supported platforms
-------------------

Currently we test ``cryptography`` on Python 2.7, 3.4+, and
PyPy 5.3+ on these operating systems.

* x86-64 CentOS 7.x
* macOS 10.12 Sierra, 10.11 El Capitan
* x86-64 Ubuntu 14.04, 16.04, and rolling
* x86-64 Debian Wheezy (7.x), Jessie (8.x), Stretch (9.x), and Sid (unstable)
* x86-64 Alpine (latest)
* 32-bit and 64-bit Python on 64-bit Windows Server 2012

We test compiling with ``clang`` as well as ``gcc`` and use the following
OpenSSL releases:

* ``OpenSSL 1.0.1``
* ``OpenSSL 1.0.1e-fips`` (``RHEL/CentOS 7``)
* ``OpenSSL 1.0.1f``
* ``OpenSSL 1.0.2-latest``
* ``OpenSSL 1.1.0-latest``
* ``OpenSSL 1.1.1-latest``

.. warning::
    Cryptography 2.4 has deprecated support for OpenSSL 1.0.1.


Building cryptography on Windows
--------------------------------

The wheel package on Windows is a statically linked build (as of 0.5) so all
dependencies are included. To install ``cryptography``, you will typically
just run

.. code-block:: console

    $ pip install cryptography

If you prefer to compile it yourself you'll need to have OpenSSL installed.
You can compile OpenSSL yourself as well or use the binaries we build for our
release infrastructure (`openssl-release`_). Be sure to download the proper
version for your architecture and Python (2010 works for Python 2.7, 3.3,
and 3.4 while 2015 is required for 3.5 and above). Wherever you place your copy
of OpenSSL you'll need to set the ``LIB`` and ``INCLUDE`` environment variables
to include the proper locations. For example:

.. code-block:: console

    C:\> \path\to\vcvarsall.bat x86_amd64
    C:\> set LIB=C:\OpenSSL-win64\lib;%LIB%
    C:\> set INCLUDE=C:\OpenSSL-win64\include;%INCLUDE%
    C:\> pip install cryptography

As of OpenSSL 1.1.0 the library names have changed from ``libeay32`` and
``ssleay32`` to ``libcrypto`` and ``libssl`` (matching their names on all other
platforms). ``cryptography`` links against the new 1.1.0 names by default. If
you need to compile ``cryptography`` against an older version then you **must**
set ``CRYPTOGRAPHY_WINDOWS_LINK_LEGACY_OPENSSL`` or else installation will fail.

If you need to rebuild ``cryptography`` for any reason be sure to clear the
local `wheel cache`_.

.. _build-on-linux:

Building cryptography on Linux
------------------------------

``cryptography`` ships a ``manylinux1`` wheel (as of 2.0) so all dependencies
are included. For users on pip 8.1 or above running on a ``manylinux1``
compatible distribution (almost everything except Alpine) all you should
need to do is:

.. code-block:: console

    $ pip install cryptography

If you are on Alpine or just want to compile it yourself then
``cryptography`` requires a compiler, headers for Python (if you're not
using ``pypy``), and headers for the OpenSSL and ``libffi`` libraries
available on your system.

Alpine
~~~~~~

Replace ``python3-dev`` with ``python-dev`` if you're using Python 2.

.. code-block:: console

    $ sudo apk add gcc musl-dev python3-dev libffi-dev openssl-dev

If you get an error with ``openssl-dev`` you may have to use ``libressl-dev``.

Debian/Ubuntu
~~~~~~~~~~~~~

Replace ``python3-dev`` with ``python-dev`` if you're using Python 2.

.. code-block:: console

    $ sudo apt-get install build-essential libssl-dev libffi-dev python3-dev

RHEL/CentOS
~~~~~~~~~~~

.. code-block:: console

    $ sudo yum install redhat-rpm-config gcc libffi-devel python-devel \
        openssl-devel


Building
~~~~~~~~

You should now be able to build and install cryptography. To avoid getting
the pre-built wheel on ``manylinux1`` distributions you'll need to use
``--no-binary``.

.. code-block:: console

    $ pip install cryptography --no-binary cryptography


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

    OPENSSL_1.1.0E_CUSTOM {
        global:
            *;
    };

You should replace the version string on the first line as appropriate for your
build.

Static Wheels
~~~~~~~~~~~~~

Cryptography ships statically-linked wheels for macOS, Windows, and Linux (via
``manylinux1``). This allows compatible environments to use the most recent
OpenSSL, regardless of what is shipped by default on those platforms. Some
Linux distributions (most notably Alpine) are not ``manylinux1`` compatible so
we cannot distribute wheels for them.

However, you can build your own statically-linked wheels that will work on your
own systems. This will allow you to continue to use relatively old Linux
distributions (such as LTS releases), while making sure you have the most
recent OpenSSL available to your Python programs.

To do so, you should find yourself a machine that is as similar as possible to
your target environment (e.g. your production environment): for example, spin
up a new cloud server running your target Linux distribution. On this machine,
install the Cryptography dependencies as mentioned in :ref:`build-on-linux`.
Please also make sure you have `virtualenv`_ installed: this should be
available from your system package manager.

Then, paste the following into a shell script. You'll need to populate the
``OPENSSL_VERSION`` variable. To do that, visit `openssl.org`_ and find the
latest non-FIPS release version number, then set the string appropriately. For
example, for OpenSSL 1.0.2k, use ``OPENSSL_VERSION="1.0.2k"``.

When this shell script is complete, you'll find a collection of wheel files in
a directory called ``wheelhouse``. These wheels can be installed by a
sufficiently-recent version of ``pip``. The Cryptography wheel in this
directory contains a statically-linked OpenSSL binding, which ensures that you
have access to the most-recent OpenSSL releases without corrupting your system
dependencies.

.. code-block:: console

    set -e

    OPENSSL_VERSION="VERSIONGOESHERE"
    CWD=$(pwd)

    virtualenv env
    . env/bin/activate
    pip install -U setuptools
    pip install -U wheel pip
    curl -O https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
    tar xvf openssl-${OPENSSL_VERSION}.tar.gz
    cd openssl-${OPENSSL_VERSION}
    ./config no-shared no-ssl2 no-ssl3 -fPIC --prefix=${CWD}/openssl
    make && make install
    cd ..
    CFLAGS="-I${CWD}/openssl/include" LDFLAGS="-L${CWD}/openssl/lib" pip wheel --no-binary :all: cryptography

Building cryptography on macOS
------------------------------

.. note::

    If installation gives a ``fatal error: 'openssl/aes.h' file not found``
    see the :doc:`FAQ </faq>` for information about how to fix this issue.

The wheel package on macOS is a statically linked build (as of 1.0.1) so for
users with pip 8 or above you only need one step:

.. code-block:: console

    $ pip install cryptography

If you want to build cryptography yourself or are on an older macOS version,
cryptography requires the presence of a C compiler, development headers, and
the proper libraries. On macOS much of this is provided by Apple's Xcode
development tools.  To install the Xcode command line tools (on macOS 10.9+)
open a terminal window and run:

.. code-block:: console

    $ xcode-select --install

This will install a compiler (clang) along with (most of) the required
development headers.

You'll also need OpenSSL, which you can obtain from `Homebrew`_ or `MacPorts`_.
Cryptography does **not** support Apple's deprecated OpenSSL distribution.

To build cryptography and dynamically link it:

`Homebrew`_

.. code-block:: console

    $ brew install openssl@1.1
    $ env LDFLAGS="-L$(brew --prefix openssl@1.1)/lib" CFLAGS="-I$(brew --prefix openssl@1.1)/include" pip install cryptography

`MacPorts`_:

.. code-block:: console

    $ sudo port install openssl
    $ env LDFLAGS="-L/opt/local/lib" CFLAGS="-I/opt/local/include" pip install cryptography

You can also build cryptography statically:

`Homebrew`_

.. code-block:: console

    $ brew install openssl@1.1
    $ env CRYPTOGRAPHY_SUPPRESS_LINK_FLAGS=1 LDFLAGS="$(brew --prefix openssl@1.1)/lib/libssl.a $(brew --prefix openssl@1.1)/lib/libcrypto.a" CFLAGS="-I$(brew --prefix openssl@1.1)/include" pip install cryptography

`MacPorts`_:

.. code-block:: console

    $ sudo port install openssl
    $ env CRYPTOGRAPHY_SUPPRESS_LINK_FLAGS=1 LDFLAGS="/opt/local/lib/libssl.a /opt/local/lib/libcrypto.a" CFLAGS="-I/opt/local/include" pip install cryptography

If you need to rebuild ``cryptography`` for any reason be sure to clear the
local `wheel cache`_.


.. _`Homebrew`: https://brew.sh
.. _`MacPorts`: https://www.macports.org
.. _`openssl-release`: https://ci.cryptography.io/job/cryptography-support-jobs/job/openssl-release-1.1/
.. _virtualenv: https://virtualenv.pypa.io/en/latest/
.. _openssl.org: https://www.openssl.org/source/
.. _`wheel cache`: https://pip.pypa.io/en/stable/reference/pip_install/#caching
