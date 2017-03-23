Submitting patches
==================

* Always make a new branch for your work.
* Patches should be small to facilitate easier review. `Studies have shown`_
  that review quality falls off as patch size grows. Sometimes this will result
  in many small PRs to land a single large feature.
* Larger changes should be discussed on `our mailing list`_ before submission.
* New features and significant bug fixes should be documented in the
  :doc:`/changelog`.
* You must have legal permission to distribute any code you contribute to
  ``cryptography``, and it must be available under both the BSD and Apache
  Software License Version 2.0 licenses.

If you believe you've identified a security issue in ``cryptography``, please
follow the directions on the :doc:`security page </security>`.

Code
----

When in doubt, refer to :pep:`8` for Python code. You can check if your code
meets our automated requirements by running ``flake8`` against it. If you've
installed the development requirements this will automatically use our
configuration. You can also run the ``tox`` job with ``tox -e pep8``.

`Write comments as complete sentences.`_

Class names which contains acronyms or initialisms should always be
capitalized. A class should be named ``HTTPClient``, not ``HttpClient``.

Every code file must start with the boilerplate licensing notice:

.. code-block:: python

    # This file is dual licensed under the terms of the Apache License, Version
    # 2.0, and the BSD License. See the LICENSE file in the root of this repository
    # for complete details.

Additionally, every Python code file must contain

.. code-block:: python

    from __future__ import absolute_import, division, print_function

API considerations
~~~~~~~~~~~~~~~~~~

Most projects' APIs are designed with a philosophy of "make easy things easy,
and make hard things possible". One of the perils of writing cryptographic code
is that secure code looks just like insecure code, and its results are almost
always indistinguishable. As a result, ``cryptography`` has, as a design
philosophy: "make it hard to do insecure things". Here are a few strategies for
API design that should be both followed, and should inspire other API choices:

If it is necessary to compare a user provided value with a computed value (for
example, verifying a signature), there should be an API provided that performs
the verification in a secure way (for example, using a constant time
comparison), rather than requiring the user to perform the comparison
themselves.

If it is incorrect to ignore the result of a method, it should raise an
exception, and not return a boolean ``True``/``False`` flag. For example, a
method to verify a signature should raise ``InvalidSignature``, and not return
whether the signature was valid.

.. code-block:: python

    # This is bad.
    def verify(sig):
        # ...
        return is_valid

    # Good!
    def verify(sig):
        # ...
        if not is_valid:
            raise InvalidSignature

Every recipe should include a version or algorithmic marker of some sort in its
output in order to allow transparent upgrading of the algorithms in use, as
the algorithms or parameters needed to achieve a given security margin evolve.

APIs at the :doc:`/hazmat/primitives/index` layer should always take an
explicit backend, APIs at the recipes layer should automatically use the
:func:`~cryptography.hazmat.backends.default_backend`, but optionally allow
specifying a different backend.

C bindings
~~~~~~~~~~

More information on C bindings can be found in :doc:`the dedicated
section of the documentation <c-bindings>`.

Tests
-----

All code changes must be accompanied by unit tests with 100% code coverage (as
measured by the combined metrics across our build matrix).

When implementing a new primitive or recipe ``cryptography`` requires that you
provide a set of test vectors. See :doc:`/development/test-vectors` for more
details.

Documentation
-------------

All features should be documented with prose in the ``docs`` section. To ensure
it builds and passes `doc8`_ style checks you can run ``tox -e docs``.

Because of the inherent challenges in implementing correct cryptographic
systems, we want to make our documentation point people in the right directions
as much as possible. To that end:

* When documenting a generic interface, use a strong algorithm in examples.
  (e.g. when showing a hashing example, don't use
  :class:`~cryptography.hazmat.primitives.hashes.MD5`)
* When giving prescriptive advice, always provide references and supporting
  material.
* When there is real disagreement between cryptographic experts, represent both
  sides of the argument and describe the trade-offs clearly.

When documenting a new module in the ``hazmat`` package, its documentation
should begin with the "Hazardous Materials" warning:

.. code-block:: rest

    .. hazmat::

Always prefer terminology that is most broadly accepted. For example:

* When referring to class instances use "an instance of ``Foo``"
  instead of "a ``Foo`` provider".

When referring to a hypothetical individual (such as "a person receiving an
encrypted message") use gender neutral pronouns (they/them/their).

Docstrings are typically only used when writing abstract classes, but should
be written like this if required:

.. code-block:: python

    def some_function(some_arg):
        """
        Does some things.

        :param some_arg: Some argument.
        """

So, specifically:

* Always use three double quotes.
* Put the three double quotes on their own line.
* No blank line at the end.
* Use Sphinx parameter/attribute documentation `syntax`_.


.. _`Write comments as complete sentences.`: https://nedbatchelder.com/blog/201401/comments_should_be_sentences.html
.. _`syntax`: http://sphinx-doc.org/domains.html#info-field-lists
.. _`Studies have shown`: https://smartbear.com/SmartBear/media/pdfs/11_Best_Practices_for_Peer_Code_Review.pdf
.. _`our mailing list`: https://mail.python.org/mailman/listinfo/cryptography-dev
.. _`doc8`: https://github.com/openstack/doc8
