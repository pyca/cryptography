Installation
============

You can install ``cryptography`` with ``pip``:

.. code-block:: console

    $ pip install cryptography

If this does not work please **upgrade your pip** first, as that is the
single most common cause of installation problems.

Supported platforms
-------------------

Currently we test ``cryptography`` on Python 3.7+ and PyPy3 7.3.10+ on these
operating systems.

* x86-64 RHEL 8.x
* x86-64 CentOS 9 Stream
* x86-64 Fedora (latest)
* x86-64 macOS 12 Monterey
* ARM64 macOS 13 Ventura
* x86-64 Ubuntu 20.04, 22.04, rolling
* ARM64 Ubuntu 22.04
* x86-64 Debian Buster (10.x), Bullseye (11.x), Bookworm (12.x),
  Trixie (13.x), and Sid (unstable)
* x86-64 Alpine (latest)
* ARM64 Alpine (latest)
* 32-bit and 64-bit Python on 64-bit Windows Server 2022

We test compiling with ``clang`` as well as ``gcc`` and use the following
OpenSSL releases in addition to distribution provided releases from the
above supported platforms:

* ``OpenSSL 1.1.1-latest``
* ``OpenSSL 3.0-latest``
* ``OpenSSL 3.1-latest``

We also test against the latest commit of BoringSSL as well as versions of
LibreSSL that are receiving security support at the time of a given
``cryptography`` release.


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
(VC2015 is required for 3.7 and above). Wherever you place your copy of OpenSSL
you'll need to set the ``OPENSSL_DIR`` environment variable to include the
proper location. For example:

.. code-block:: console

    C:\> \path\to\vcvarsall.bat x86_amd64
    C:\> set OPENSSL_DIR=C:\OpenSSL-win64
    C:\> pip install cryptography

You will also need to have :ref:`Rust installed and
available<installation:Rust>`.

If you need to rebuild ``cryptography`` for any reason be sure to clear the
local `wheel cache`_.

.. _build-on-linux:

Building cryptography on Linux
------------------------------

.. note::

    You should **upgrade pip** and attempt to install ``cryptography`` again
    before following the instructions to compile it below. Most Linux
    platforms will receive a binary wheel and require no compiler if you have
    an updated ``pip``!

``cryptography`` ships ``manylinux`` wheels (as of 2.0) so all dependencies
are included. For users on **pip 19.3** or above running on a ``manylinux2014``
(or greater) compatible distribution (or **pip 21.2.4** for ``musllinux``) all
you should need to do is:

.. code-block:: console

    $ pip install cryptography

If you want to compile ``cryptography`` yourself you'll need a C compiler, a
Rust compiler, headers for Python (if you're not using ``pypy``), and headers
for the OpenSSL and ``libffi`` libraries available on your system.

On all Linux distributions you will need to have :ref:`Rust installed and
available<installation:Rust>`.

Alpine
~~~~~~

.. warning::

    The Rust available by default in Alpine < 3.15 is older than the minimum
    supported version. See the :ref:`Rust installation instructions
    <installation:Rust>` for information about installing a newer Rust.

.. code-block:: console

    $ sudo apk add gcc musl-dev python3-dev libffi-dev openssl-dev cargo pkgconfig

If you get an error with ``openssl-dev`` you may have to use ``libressl-dev``.

Debian/Ubuntu
~~~~~~~~~~~~~

.. warning::

    The Rust available in Debian versions prior to Bookworm are older than the
    minimum supported version. See the :ref:`Rust installation instructions
    <installation:Rust>` for information about installing a newer Rust.

.. code-block:: console

    $ sudo apt-get install build-essential libssl-dev libffi-dev \
        python3-dev cargo pkg-config

Fedora/RHEL/CentOS
~~~~~~~~~~~~~~~~~~

.. warning::

    For RHEL and CentOS you must be on version 8.6 or newer for the command
    below to install a sufficiently new Rust. If your Rust is less than 1.56.0
    please see the :ref:`Rust installation instructions <installation:Rust>`
    for information about installing a newer Rust.

.. code-block:: console

    $ sudo dnf install redhat-rpm-config gcc libffi-devel python3-devel \
        openssl-devel cargo pkg-config


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
``manylinux`` and ``musllinux``). This allows compatible environments to use
the most recent OpenSSL, regardless of what is shipped by default on those
platforms.

If you are using a platform not covered by our wheels, you can build your own
statically-linked wheels that will work on your own systems. This will allow
you to continue to use relatively old Linux distributions (such as LTS
releases), while making sure you have the most recent OpenSSL available to
your Python programs.

To do so, you should find yourself a machine that is as similar as possible to
your target environment (e.g. your production environment): for example, spin
up a new cloud server running your target Linux distribution. On this machine,
install the Cryptography dependencies as mentioned in :ref:`build-on-linux`.
Please also make sure you have `virtualenv`_ installed: this should be
available from your system package manager.

Then, paste the following into a shell script. You'll need to populate the
``OPENSSL_VERSION`` variable. To do that, visit `openssl.org`_ and find the
latest non-FIPS release version number, then set the string appropriately. For
example, for OpenSSL 1.1.1k, use ``OPENSSL_VERSION="1.1.1k"``.

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
    OPENSSL_DIR="${CWD}/openssl" pip wheel --no-cache-dir --no-binary cryptography cryptography

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
`MacPorts`_, or directly from the Rust website. If you are linking against a
``universal2`` archive of OpenSSL, the minimum supported Rust version is
1.66.0.

Finally you need OpenSSL, which you can obtain from `Homebrew`_ or `MacPorts`_.
Cryptography does **not** support the OpenSSL/LibreSSL libraries Apple ships
in its base operating system.

To build cryptography and dynamically link it:

`Homebrew`_

.. code-block:: console

    $ brew install openssl@3 rust
    $ env OPENSSL_DIR="$(brew --prefix openssl@3)" pip install cryptography

`MacPorts`_:

.. code-block:: console

    $ sudo port install openssl rust
    $ env OPENSSL_DIR="-L/opt/local" pip install cryptography

You can also build cryptography statically:

`Homebrew`_

.. code-block:: console

    $ brew install openssl@3 rust
    $ env OPENSSL_STATIC=1 OPENSSL_DIR="$(brew --prefix openssl@3)" pip install cryptography

`MacPorts`_:

.. code-block:: console

    $ sudo port install openssl rust
    $ env OPENSSL_STATIC=1 OPENSSL_DIR="/opt/local" pip install cryptography

If you need to rebuild ``cryptography`` for any reason be sure to clear the
local `wheel cache`_.

Rust
----

.. note::

    If you are using Linux, then you should **upgrade pip** (in
    a virtual environment!) and attempt to install ``cryptography`` again before
    trying to install the Rust toolchain. On most Linux distributions, the latest
    version of ``pip`` will be able to install a binary wheel, so you won't need
    a Rust toolchain.

Building ``cryptography`` requires having a working Rust toolchain. The current
minimum supported Rust version is 1.56.0. **This is newer than the Rust some
package managers ship**, so users may need to install with the
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
.. _`wheel cache`: https://pip.pypa.io/en/stable/cli/pip_install/#caching
.. _`the Rust Project's website`: https://www.rust-lang.org/tools/install
