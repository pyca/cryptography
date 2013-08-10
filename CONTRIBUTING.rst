Process
=======

This repository has a mandatory code review policy. Contributions
should happen through pull requests. Never commit to ``master``
directly.

Code
====

When in doubt, refer to `PEP 8`_ for Python code.

Every code file must start with the boilerplate notice of the Apache License.
Additionally, every Python code file must contain

.. code-block:: python

    from __future__ import absolute_import, division, print_function

Docs
====

Write docstrings like this:

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


.. _`PEP 8`: http://www.peps.io/8/
.. _`syntax`: http://sphinx-doc.org/domains.html#info-field-lists
