Getting started
===============

Development dependencies
------------------------

Working on ``cryptography`` requires the installation of a small number of
development dependencies in addition to the dependencies for
:doc:`/installation` (including :ref:`Rust<installation:rust>`). These are
handled by the use of ``nox``, which can be installed with ``pip``.

.. code-block:: console

    $ # Create a virtualenv and activate it
    $ # Set up your cryptography build environment
    $ pip install nox
    $ nox -e local

OpenSSL on macOS
~~~~~~~~~~~~~~~~

You must have installed `OpenSSL`_ (via `Homebrew`_  or `MacPorts`_) before
invoking ``nox`` or else pip will fail to compile.

Running tests
-------------

``cryptography`` unit tests are found in the ``tests/`` directory and are
designed to be run using `pytest`_. ``nox`` automatically invokes ``pytest``
and other required checks for ``cryptography``:

.. code-block:: console

    $ nox -e local


You can also specify a subset of tests to run as positional arguments:

.. code-block:: console

    $ # run the whole x509 testsuite, plus the fernet tests
    $ nox -e local -- tests/x509/ tests/test_fernet.py

Building the docs
-----------------

Building the docs on non-Windows platforms requires manually installing
the C library ``libenchant`` (`installation instructions`_).
The docs can be built using ``nox``:

.. code-block:: console

    $ nox -e docs


.. _`Homebrew`: https://brew.sh
.. _`MacPorts`: https://www.macports.org
.. _`OpenSSL`: https://www.openssl.org
.. _`pytest`: https://pypi.org/project/pytest/
.. _`nox`: https://pypi.org/project/nox/
.. _`virtualenv`: https://pypi.org/project/virtualenv/
.. _`pip`: https://pypi.org/project/pip/
.. _`as documented here`: https://docs.rs/openssl/latest/openssl/#automatic
.. _`installation instructions`: https://pyenchant.github.io/pyenchant/install.html#installing-the-enchant-c-library
