Installation
============

You can install ``cryptography`` with ``pip``:

.. code-block:: console

    $ pip install cryptography

Supported platforms
-------------------

Currently we test ``cryptography`` on Python 2.6, 2.7, 3.3, 3.4, 3.5, and PyPy
2.6+ on these operating systems.

* x86-64 CentOS 7.x, 6.4 and CentOS 5.x
* x86-64 FreeBSD 10
* OS X 10.11 El Capitan, 10.10 Yosemite, 10.9 Mavericks, 10.8 Mountain Lion,
  and 10.7 Lion
* x86-64 Ubuntu 12.04 LTS and Ubuntu 14.04 LTS
* x86-64 Debian Wheezy (7.x), Jessie (8.x), and Debian Sid (unstable)
* 32-bit and 64-bit Python on 64-bit Windows Server 2012

.. warning::
    Python 2.6 is no longer supported by the Python core team. A future version
    of cryptography will drop support for this version.

We test compiling with ``clang`` as well as ``gcc`` and use the following
OpenSSL releases:

* ``OpenSSL 0.9.8e-fips-rhel5`` (``RHEL/CentOS 5``)
* ``OpenSSL 0.9.8k``
* ``OpenSSL 1.0.0-fips`` (``RHEL/CentOS 6.4``)
* ``OpenSSL 1.0.1``
* ``OpenSSL 1.0.1e-fips`` (``RHEL/CentOS 7``)
* ``OpenSSL 1.0.1j-freebsd``
* ``OpenSSL 1.0.1f``
* ``OpenSSL 1.0.2-latest``

.. warning::
    OpenSSL versions 0.9.8 and 1.0.0 are no longer supported by the OpenSSL
    project. Cryptography 1.4 has dropped support for OpenSSL 0.9.8, see the
    :doc:`FAQ </faq>` for more details.

On Windows
----------

The wheel package on Windows is a statically linked build (as of 0.5) so all
dependencies are included. Just run

.. code-block:: console

    $ pip install cryptography

If you prefer to compile it yourself you'll need to have OpenSSL installed.
You can compile OpenSSL yourself as well or use the binaries we build for our
release infrastructure (`openssl-release`_). Be sure to download the proper
version for your architecture and Python (2010 works for Python 2.6, 2.7, 3.3,
and 3.4 while 2015 is required for 3.5). Wherever you place your copy
of OpenSSL you'll need to set the ``LIB`` and ``INCLUDE`` environment variables
to include the proper locations. For example:

.. code-block:: console

    C:\> \path\to\vcvarsall.bat x86_amd64
    C:\> set LIB=C:\OpenSSL-win64\lib;%LIB%
    C:\> set INCLUDE=C:\OpenSSL-win64\include;%INCLUDE%
    C:\> pip install cryptography

If you need to rebuild ``cryptography`` for any reason be sure to clear the
local `wheel cache`_.

.. _build-on-linux:

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

Static Wheels
~~~~~~~~~~~~~

Cryptography ships statically-linked wheels for OS X and Windows, ensuring that
these platforms can always use the most-recent OpenSSL, regardless of what is
shipped by default on those platforms. As a result of various difficulties
around Linux binary linking, Cryptography cannot do the same on Linux.

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
example, for OpenSSL 1.0.2d, use ``OPENSSL_VERSION="1.0.2d"``.

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
    curl -O https://openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
    tar xvf openssl-${OPENSSL_VERSION}.tar.gz
    cd openssl-${OPENSSL_VERSION}
    ./config no-shared no-ssl2 -fPIC --prefix=${CWD}/openssl
    make && make install
    cd ..
    CFLAGS="-I${CWD}/openssl/include" LDFLAGS="-L${CWD}/openssl/lib" pip wheel --no-use-wheel cryptography

Building cryptography on OS X
-----------------------------

.. note::

    If installation gives a ``fatal error: 'openssl/aes.h' file not found``
    see the :doc:`FAQ </faq>` for information about how to fix this issue.

The wheel package on OS X is a statically linked build (as of 1.0.1) so for
users with pip 8 or above you only need one step:

.. code-block:: console

    $ pip install cryptography

If you want to build cryptography yourself or are on an older OS X version
cryptography requires the presence of a C compiler, development headers, and
the proper libraries. On OS X much of this is provided by Apple's Xcode
development tools.  To install the Xcode command line tools (on OS X 10.9+)
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

    $ brew install openssl
    $ env LDFLAGS="-L$(brew --prefix openssl)/lib" CFLAGS="-I$(brew --prefix openssl)/include" pip install cryptography

`MacPorts`_:

.. code-block:: console

    $ sudo port install openssl
    $ env LDFLAGS="-L/opt/local/lib" CFLAGS="-I/opt/local/include" pip install cryptography

You can also build cryptography statically:

`Homebrew`_

.. code-block:: console

    $ brew install openssl
    $ env CRYPTOGRAPHY_OSX_NO_LINK_FLAGS=1 LDFLAGS="$(brew --prefix openssl)/lib/libssl.a $(brew --prefix openssl)/lib/libcrypto.a" CFLAGS="-I$(brew --prefix openssl)/include" pip install cryptography

`MacPorts`_:

.. code-block:: console

    $ sudo port install openssl
    $ env CRYPTOGRAPHY_OSX_NO_LINK_FLAGS=1 LDFLAGS="/opt/local/lib/libssl.a /opt/local/lib/libcrypto.a" CFLAGS="-I/opt/local/include" pip install cryptography

If you need to rebuild ``cryptography`` for any reason be sure to clear the
local `wheel cache`_.

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
.. _`MacPorts`: https://www.macports.org
.. _`openssl-release`: https://jenkins.cryptography.io/job/openssl-release/
.. _`bug in conda`: https://github.com/conda/conda-recipes/issues/110
.. _`Greg Wilson's blog post`: https://software-carpentry.org/blog/2014/04/mr-biczo-was-right.html
.. _virtualenv: https://virtualenv.pypa.io/en/latest/
.. _openssl.org: https://openssl.org/source/
.. _`wheel cache`: https://pip.pypa.io/en/stable/reference/pip_install/#caching
