Contributing
============

Process
-------

As an open source project, ``cryptography`` welcomes contributions of all
forms. These can include:

* Bug reports and feature requests
* Pull requests for both code and documentation
* Patch reviews

You can file bugs and submit pull requests on `GitHub`_. To discuss larger
changes you can start a conversation on `our mailing list`_.

Because cryptography is so complex, and the implications of getting it wrong so
devastating, ``cryptography`` has a strict code review policy:

* Patches must *never* be pushed directly to ``master``, all changes (even the
  most trivial typo fixes!) must be submitted as a pull request.
* A committer may *never* merge their own pull request, a second party must
  merge their changes. If multiple people work on a pull request, the merger
  may not be any of them.
* A patch which breaks tests, or introduces regressions by changing or removing
  existing tests should not be merged. Tests must always be passing on
  ``master``.
* If somehow the tests get into a failing state on ``master`` (such as by a
  backwards incompatible release of a dependency) no pull requests may be
  merged until this is rectified.

The purpose of these policies is to minimize the chances we merge a change
which jeopardizes our users' security.

We do not yet have a formal security contact. To report security issues in
``cryptography`` you should email ``alex.gaynor@gmail.com``, messages may be
encrypted with PGP to key fingerprint
``E27D 4AA0 1651 72CB C5D2  AF2B 125F 5C67 DFE9 4084`` (this public key is
available from most commonly-used keyservers).

Code
----

When in doubt, refer to `PEP 8`_ for Python code.

Every code file must start with the boilerplate notice of the Apache License.
Additionally, every Python code file must contain

.. code-block:: python

    from __future__ import absolute_import, division, print_function

Documentation
-------------

All features should be documented with prose.

Docstrings should be written like this:

.. code-block:: python

    def some_function(some_arg):
        """
        Does some things.

        :param some_arg: Some argument.
        """

So, specifically:

- Always use three double quotes.
- Put the three double quotes on their own line.
- No blank line at the end.
- Use Sphinx parameter/attribute documentation `syntax`_.

Development
-----------

Working on ``cryptography`` requires the installation of a small number of
development dependencies.
The list of development dependencies can be found in ``requirements-dev.txt``.
We recommend that you install these using `virtualenv`_ and `pip`_.
The following example shows how to create a ``cryptography`` development
environment on Linux:

.. code-block:: sh

   cd ~/projects
   git clone git@github.com:<GITHUB_USER>/cryptography.git
   cd cryptography
   mkdir -p ~/.virtualenvs/cryptography
   virtualenv --no-site-packages ~/.virtualenvs/cryptography
   source ~/.virtualenvs/cryptography/bin/activate
   pip install -r requirements-dev.txt
   pip install -e .

You are now ready to run the tests and build the documentation.
Those steps are described in the next sections.

Testing
-------

``cryptography`` unit tests are found in the ``tests`` directory.
They are designed to be run using `pytest`_ as follows

.. code-block:: sh

   py.test tests
   ...
   4294 passed in 15.24 seconds

This runs the tests with the default Python interpreter.

You can also verify that the tests pass on other supported Python interpreters.
For this we use `tox`_, which will automatically create a `virtualenv`_ for
each supported Python version and run the tests.
Here is an example:

.. code-block:: sh

   tox -l
   ...
   py33

   tox -e py33
   ...
   py33: commands succeeded
   congratulations :)

`tox`_ can also be used to build the ``cryptography`` documentation.
That is described in the next section.

Building Documentation
----------------------

``cryptography`` documentation is stored in the ``docs`` directory.
It is written in `ReST`_ and built using `sphinx`_.

The simplest way to build the documentation is to use `tox`_.
The following example demonstrates how:

.. code-block:: sh

   tox -e doc
   ...
   docs: commands succeeded
   congratulations :)

The HTML documentation can now be found in the ``docs/_build/html``
sub-directory.

.. code-block:: sh

   firefox docs/_build/html/index.html


.. _`GitHub`: https://github.com/alex/cryptography
.. _`our mailing list`: https://mail.python.org/mailman/listinfo/cryptography-dev
.. _`PEP 8`: http://www.peps.io/8/
.. _`syntax`: http://sphinx-doc.org/domains.html#info-field-lists
.. _`pytest`: https://pypi.python.org/pypi/pytest
.. _`tox`: https://pypi.python.org/pypi/tox
.. _`virtualenv`: https://pypi.python.org/pypi/virtualenv
.. _`pip`: https://pypi.python.org/pypi/pip
.. _`sphinx`: https://pypi.python.org/pypi/sphinx
.. _`ReST`: http://docutils.sourceforge.net/rst.html
