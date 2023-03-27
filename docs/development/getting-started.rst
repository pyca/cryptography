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

You must have installed `OpenSSL`_ via `Homebrew`_ or `MacPorts`_ and must set
``CFLAGS`` and ``LDFLAGS`` environment variables before running ``nox``
otherwise pip will fail with include errors.

For example, with `Homebrew`_:

.. code-block:: console

    $ env LDFLAGS="-L$(brew --prefix openssl@1.1)/lib" \
        CFLAGS="-I$(brew --prefix openssl@1.1)/include" \
        nox -e tests -p py310

Alternatively for a static build you can specify
``CRYPTOGRAPHY_SUPPRESS_LINK_FLAGS=1`` and ensure ``LDFLAGS`` points to the
absolute path for the `OpenSSL`_ libraries before calling pip.

.. tip::
    You will also need to set these values when `Building documentation`_.

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
