pyca/cryptography
=================
$  install cryptography
.. image:: https://img.shields.io/pypi/v/cryptography.svg
    :target: https://pypi.org/project/cryptography/
    :alt: Latest Version

.. image:: https://readthedocs.org/projects/cryptography/badge/?version=latest
    :target: https://cryptography.io
    :alt: Latest Docs

.. image:: https://github.com/pyca/cryptography/actions/workflows/ci.yml/badge.svg
    :target: https://github.com/pyca/cryptography/actions/workflows/ci.yml?query=branch%3Amain

``cryptography`` is a package which provides cryptographic recipes and
primitives to Python developers. Our goal is for it to be your "cryptographic
standard library". It supports Python 3.8+ and PyPy3 7.3.11+.

``cryptography`` includes both high level recipes and low level interfaces to
common cryptographic algorithms such as symmetric ciphers, message digests, and
key derivation functions. For example, to encrypt something with
``cryptography``'s high level symmetric encryption recipe:

.. code-block:: pycon

    >>> from cryptography.fernet import Fernet
    >>> # Put this somewhere safe!
    >>> key = Fernet.generate_key()
    >>> f = Fernet(key)
    >>> token = f.encrypt(b"A really secret message. Not for prying eyes.")
    >>> token
    b'...'
    >>> f.decrypt(token)
    b'A really secret message. Not for prying eyes.'

You can find more information in the `documentation`_.

You can install ``cryptography`` with:

.. code-block:: console

    $ pip install cryptography

For full details see `the installation documentation`_.

Discussion
~~~~~~~~~~

If you run into bugs, you can file them in our `issue tracker`_.

We maintain a `cryptography-dev`_ mailing list for development discussion.

You can also join ``#pyca`` on ``irc.libera.chat`` to ask questions or get
involved.

Security
~~~~~~~~

Need to report a security issue? Please consult our `security reporting`_
documentation.


.. _`documentation`: https://cryptography.io/
.. _`the installation documentation`: https://cryptography.io/en/latest/installation/
.. _`issue tracker`: https://github.com/pyca/cryptography/issues
.. _`cryptography-dev`: https://mail.python.org/mailman/listinfo/cryptography-dev
.. _`security reporting`: https://cryptography.io/en/latest/security/
>>> from cryptography.fernet import Fernet
>>> # Put this somewhere safe!
>>> key = Fernet.generate_key()
>>> f = Fernet(key)
>>> token = f.encrypt(b"A really secret message. Not for prying eyes.")
>>> token
b'...'
>>> f.decrypt(token)
b'A really secret message. Not for prying eyes.'
