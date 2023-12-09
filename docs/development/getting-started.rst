Getting started
===============

Development dependencies
------------------------

Start by reading the installation documentation.
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

OpenSSL on macOS
~~~~~~~~~~~~~~~~

You must have installed `OpenSSL`_ (via `Homebrew`_ , `MacPorts`_) before
invoking ``nox`` or else pip will fail to compile.

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


Running tests for TDD
~~~~~~~~~~~~~~~~~~~~~

.. warning::

    When not using `nox`, it's easy to screw up the build system,
    Failing to rebuild any extension module will get you confusing
    and inconsistent results.
    When in doubt, fallback to using `nox`.

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


.. _`Homebrew`: https://brew.sh
.. _`MacPorts`: https://www.macports.org
.. _`OpenSSL`: https://www.openssl.org
.. _`pytest`: https://pypi.org/project/pytest/
.. _`nox`: https://pypi.org/project/nox/
.. _`virtualenv`: https://pypi.org/project/virtualenv/
.. _`pip`: https://pypi.org/project/pip/
.. _`as documented here`: https://docs.rs/openssl/latest/openssl/#automatic
