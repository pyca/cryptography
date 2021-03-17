Installation
============

You can install ``cryptography`` with ``pip``:

.. code-block:: console

    $ pip install cryptography

If this does not work please **upgrade your pip** first, as that is the
single most common cause of installation problems.

Supported platforms
-------------------

Currently we test ``cryptography`` on Python 3.6+ and PyPy3 7.3.1 on these
operating systems.

* x86-64 & AArch64 CentOS 8.x
* x86-64 Fedora (latest)
* x86-64 macOS 10.15 Catalina
* x86-64 & AArch64 Ubuntu 18.04, 20.04
* x86-64 Ubuntu rolling
* x86-64 Debian Stretch (9.x), Buster (10.x), Bullseye (11.x), and Sid
  (unstable)
* x86-64 Alpine (latest)
* 32-bit and 64-bit Python on 64-bit Windows Server 2019

We test compiling with ``clang`` as well as ``gcc`` and use the following
OpenSSL releases:

* ``OpenSSL 1.1.0-latest``
* ``OpenSSL 1.1.1-latest``


Building cryptography on Windows
--------------------------------

The wheel package on Windows is a statically linked build (as of 0.5) so all
dependencies are included. To install ``cryptography``, you will typically
just run

.. code-block:: console

    $ pip install cryptography

If you prefer to compile it yourself you'll need to have OpenSSL installed.
You can compile OpenSSL yourself as well or use `a binary distribution`_.
Be sure to download the proper version for your architecture and Python
(VC2015 is required for 3.6 and above). Wherever you place your copy of OpenSSL
you'll need to set the ``LIB`` and ``INCLUDE`` environment variables to include
the proper locations. For example:

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

You will also need to have :ref:`Rust installed and
available<installation:Rust>`.

If you need to rebuild ``cryptography`` for any reason be sure to clear the
local `wheel cache`_.

.. _build-on-linux:

Building cryptography on Linux
------------------------------

.. note::

    If you are on RHEL/CentOS/Fedora/Debian/Ubuntu or another distribution
    derived from the preceding list, then you should **upgrade pip** and
    attempt to install ``cryptography`` again before following the instructions
    to compile it below. These platforms will receive a binary wheel and
    require no compiler if you have an updated ``pip``!

``cryptography`` ships ``manylinux`` wheels (as of 2.0) so all dependencies
are included. For users on **pip 19.0** or above running on a ``manylinux2010``
(or greater) compatible distribution (almost everything **except Alpine**) all
you should need to do is:

.. code-block:: console

    $ pip install cryptography

If you are on Alpine or just want to compile it yourself then
``cryptography`` requires a C compiler, a Rust compiler, headers for Python (if
you're not using ``pypy``), and headers for the OpenSSL and ``libffi`` libraries
available on your system.

On all Linux distributions you will need to have :ref:`Rust installed and
available<installation:Rust>`.

Alpine
~~~~~~

.. warning::

    The Rust available by default in Alpine < 3.12 is older than the minimum
    supported version. See the :ref:`Rust installation instructions
    <installation:Rust>` for information about installing a newer Rust.

.. code-block:: console

    $ sudo apk add gcc musl-dev python3-dev libffi-dev openssl-dev cargo

If you get an error with ``openssl-dev`` you may have to use ``libressl-dev``.

Debian/Ubuntu
~~~~~~~~~~~~~

.. warning::

    The Rust available in current Debian stable and some Ubuntu versions is
    older than the minimum supported version. Ubuntu 18.04 and 20.04 are
    sufficiently new, but otherwise please see the
    :ref:`Rust installation instructions <installation:Rust>` for information
    about installing a newer Rust.

.. code-block:: console

    $ sudo apt-get install build-essential libssl-dev libffi-dev \
        python3-dev cargo

Fedora/RHEL 8/CentOS 8
~~~~~~~~~~~~~~~~~~~~~~

.. warning::

    For RHEL and CentOS you must be on version 8.3 or newer for the command
    below to install a sufficiently new Rust. If your Rust is less than 1.41.0
    please see the :ref:`Rust installation instructions <installation:Rust>`
    for information about installing a newer Rust.

.. code-block:: console

    $ sudo dnf install redhat-rpm-config gcc libffi-devel python3-devel \
        openssl-devel cargo

RHEL 7/CentOS 7
~~~~~~~~~~~~~~~

.. warning::

    You must install Rust using the :ref:`Rust installation instructions
    <installation:Rust>`. ``cryptography`` requires a Rust version newer than
    what is provided in the distribution packages.

.. code-block:: console

    $ sudo yum install redhat-rpm-config gcc libffi-devel python-devel \
        openssl-devel


Building
~~~~~~~~

You should now be able to build and install cryptography. To avoid getting
the pre-built wheel on ``manylinux`` compatible distributions you'll need to
use ``--no-binary``.

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

    $ ./config -Wl,-Bsymbolic-functions -fPIC shared

Static Wheels
~~~~~~~~~~~~~

Cryptography ships statically-linked wheels for macOS, Windows, and Linux (via
``manylinux``). This allows compatible environments to use the most recent
OpenSSL, regardless of what is shipped by default on those platforms. Some
Linux distributions (most notably Alpine) are not ``manylinux`` compatible so
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
development tools.  To install the Xcode command line tools (on macOS 10.10+)
open a terminal window and run:

.. code-block:: console

    $ xcode-select --install

This will install a compiler (clang) along with (most of) the required
development headers.

You will also need to have :ref:`Rust installed and
available<installation:Rust>`, which can be obtained from `Homebrew`_,
`MacPorts`_, or directly from the Rust website.

Finally you need OpenSSL, which you can obtain from `Homebrew`_ or `MacPorts`_.
Cryptography does **not** support the OpenSSL/LibreSSL libraries Apple ships
in its base operating system.

To build cryptography and dynamically link it:

`Homebrew`_

.. code-block:: console

    $ brew install openssl@1.1 rust
    $ env LDFLAGS="-L$(brew --prefix openssl@1.1)/lib" CFLAGS="-I$(brew --prefix openssl@1.1)/include" pip install cryptography

`MacPorts`_:

.. code-block:: console

    $ sudo port install openssl rust
    $ env LDFLAGS="-L/opt/local/lib" CFLAGS="-I/opt/local/include" pip install cryptography

You can also build cryptography statically:

`Homebrew`_

.. code-block:: console

    $ brew install openssl@1.1 rust
    $ env CRYPTOGRAPHY_SUPPRESS_LINK_FLAGS=1 LDFLAGS="$(brew --prefix openssl@1.1)/lib/libssl.a $(brew --prefix openssl@1.1)/lib/libcrypto.a" CFLAGS="-I$(brew --prefix openssl@1.1)/include" pip install cryptography

`MacPorts`_:

.. code-block:: console

    $ sudo port install openssl rust
    $ env CRYPTOGRAPHY_SUPPRESS_LINK_FLAGS=1 LDFLAGS="/opt/local/lib/libssl.a /opt/local/lib/libcrypto.a" CFLAGS="-I/opt/local/include" pip install cryptography

If you need to rebuild ``cryptography`` for any reason be sure to clear the
local `wheel cache`_.

Rust
----

.. note::

    If you are on RHEL/CentOS/Fedora/Debian/Ubuntu or another distribution
    derived from the preceding list, then you should **upgrade pip** (in
    a virtual environment!) and attempt to install ``cryptography`` again
    before trying to install the Rust toolchain. These platforms will receive
    a binary wheel and require no compiler if you have an updated ``pip``!

Building ``cryptography`` requires having a working Rust toolchain. The current
minimum supported Rust version is 1.41.0. **This is newer than the Rust most
package managers ship**, so users will likely need to install with the
instructions below.

Instructions for installing Rust can be found on `the Rust Project's website`_.
We recommend installing Rust with ``rustup`` (as documented by the Rust
Project) in order to ensure you have a recent version.

Rust is only required when building ``cryptography``, meaning that you may
install it for the duration of your ``pip install`` command and then remove it
from a system. A Rust toolchain is not required to **use** ``cryptography``. In
deployments such as ``docker``, you may use a multi-stage ``Dockerfile`` where
you install Rust during the build phase but do not install it in the runtime
image. This is the same as the C compiler toolchain which is also required to
build ``cryptography``, but not afterwards.

.. _`Homebrew`: https://brew.sh
.. _`MacPorts`: https://www.macports.org
.. _`a binary distribution`: https://wiki.openssl.org/index.php/Binaries
.. _virtualenv: https://virtualenv.pypa.io/en/latest/
.. _openssl.org: https://www.openssl.org/source/
.. _`wheel cache`: https://pip.pypa.io/en/stable/reference/pip_install/#caching
.. _`the Rust Project's website`: https://www.rust-lang.org/tools/install
