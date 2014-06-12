Getting started
===============

Working on ``cryptography`` requires the installation of a small number of
development dependencies in addition to the depedencies for `installation`_.
These are listed in ``dev-requirements.txt`` and they can be installed in a
`virtualenv`_ using `pip`_. Once you've installed the dependencies, install
``cryptography`` in ``editable`` mode. For example:

.. code-block:: console

    $ # Create a virtualenv and activate it
    $ pip install --requirement dev-requirements.txt
    $ pip install --editable .

You are now ready to run the tests and build the documentation.

Running tests
~~~~~~~~~~~~~

``cryptography`` unit tests are found in the ``tests/`` directory and are
designed to be run using `pytest`_. `pytest`_ will discover the tests
automatically, so all you have to do is:

.. code-block:: console

    $ py.test
    ...
    62746 passed in 220.43 seconds

This runs the tests with the default Python interpreter.

You can also verify that the tests pass on other supported Python interpreters.
For this we use `tox`_, which will automatically create a `virtualenv`_ for
each supported Python version and run the tests. For example:

.. code-block:: console

    $ tox
    ...
    ERROR:   py26: InterpreterNotFound: python2.6
     py27: commands succeeded
    ERROR:   pypy: InterpreterNotFound: pypy
    ERROR:   py32: InterpreterNotFound: python3.2
     py33: commands succeeded
     docs: commands succeeded
     pep8: commands succeeded

You may not have all the required Python versions installed, in which case you
will see one or more ``InterpreterNotFound`` errors.


Explicit backend selection
~~~~~~~~~~~~~~~~~~~~~~~~~~

While testing you may want to run tests against a subset of the backends that
cryptography supports. Explicit backend selection can be done via the
``--backend`` flag. This flag should be passed to ``py.test`` with a comma
delimited list of backend names.


.. code-block:: console

    $ tox -- --backend=openssl
    $ py.test --backend=openssl,commoncrypto

Building documentation
~~~~~~~~~~~~~~~~~~~~~~

``cryptography`` documentation is stored in the ``docs/`` directory. It is
written in `reStructured Text`_ and rendered using `Sphinx`_.

Use `tox`_ to build the documentation. For example:

.. code-block:: console

    $ tox -e docs
    ...
    docs: commands succeeded
    congratulations :)

The HTML documentation index can now be found at
``docs/_build/html/index.html``.

.. _`pytest`: https://pypi.python.org/pypi/pytest
.. _`tox`: https://pypi.python.org/pypi/tox
.. _`virtualenv`: https://pypi.python.org/pypi/virtualenv
.. _`pip`: https://pypi.python.org/pypi/pip
.. _`sphinx`: https://pypi.python.org/pypi/Sphinx
.. _`reStructured Text`: http://sphinx-doc.org/rest.html
.. _`installation`: https://cryptography.io/en/latest/installation/
