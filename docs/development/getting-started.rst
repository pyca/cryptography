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