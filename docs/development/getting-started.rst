Getting started
===============

Development dependencies
------------------------

Working on ``cryptography`` requires the installation of a small number of
development dependencies in addition to the dependencies for
:doc:`/installation`. These are handled by the use of ``nox``, which can be
installed with ``pip``.

.. code-block:: console

    $ # Create a virtualenv and activate it
    $ # Set up your cryptography build environment
    $ pip install nox
    $ # Specify your Python version here.
    $ nox -e tests -p py310


Rust dependencies on Linux
~~~~~~~~~~~~~~~~~~~~~~~~~~

Here are the notes for Ubuntu.
I hope they help and you can adapt them to your OS.
Make sure to have the following packages installed, for OpenSSL development::

    apt install pkgconf libssl-dev

The easies way to get a working `rust` dev environment is via https://rustup.rs
and have it installed in your home directory.

After `rustup` is installed, you can install the optional rust dev tools::

    rustup component add llvm-tools


OpenSSL on macOS
~~~~~~~~~~~~~~~~

You must have installed `OpenSSL`_ (via `Homebrew`_ , `MacPorts`_, or a custom
build) and must configure the build `as documented here`_ before calling
``nox`` or else pip will fail to compile.


Running tests
-------------

``cryptography`` unit tests are found in the ``tests/`` directory and are
designed to be run using `pytest`_. ``nox`` automatically invokes ``pytest``:

.. code-block:: console

    $ nox -e tests -p py310
    ...
    62746 passed in 220.43 seconds


You can also specify a subset of tests to run as positional arguments:

.. code-block:: console

    $ # run the whole x509 testsuite, plus the fernet tests
    $ nox -e tests -p py310 -- tests/x509/ tests/test_fernet.py

For TDD you might want to speed up the test run cycle.
After activating your virtualenv, install the dev requirements
and then install the project in edit mode.

.. code-block:: console

    $ pip install -e vectors/
    $ pip install -e .[ssh,test,test-randomorder]

If you are changing the OpenSSL bindings from `src/_cffi_src` you will need
to rebuild the rust OpenSSL bindings.
The easiest method is to just reinstall in edit mode.

.. code-block:: console

    $ # Re-build the binding and other extensions.
    $ pip install -e .
    $ # Then re-run the tests.
    $ pytest tests/hazmat/bindings/


Building documentation
----------------------

``cryptography`` documentation is stored in the ``docs/`` directory. It is
written in `reStructured Text`_ and rendered using `Sphinx`_.

Use `nox`_ to build the documentation. For example:

.. code-block:: console

    $ nox -e docs
    ...
    nox > Session docs was successful.

The HTML documentation index can now be found at
``docs/_build/html/index.html``.

.. _`Homebrew`: https://brew.sh
.. _`MacPorts`: https://www.macports.org
.. _`OpenSSL`: https://www.openssl.org
.. _`pytest`: https://pypi.org/project/pytest/
.. _`nox`: https://pypi.org/project/nox/
.. _`virtualenv`: https://pypi.org/project/virtualenv/
.. _`pip`: https://pypi.org/project/pip/
.. _`sphinx`: https://pypi.org/project/Sphinx/
.. _`reStructured Text`: https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html
.. _`as documented here`: https://docs.rs/openssl/latest/openssl/#automatic
