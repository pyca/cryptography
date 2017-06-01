Welcome to ``pyca/cryptography``
================================

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
    '...'
    >>> f.decrypt(token)
    'A really secret message. Not for prying eyes.'

If you are interested in learning more about the field of cryptography, we
recommend `Crypto 101, by Laurens Van Houtven`_.

Installation
------------
You can install ``cryptography`` with ``pip``:

.. code-block:: console

    $ pip install cryptography

See :doc:`Installation <installation>` for more information.

.. _cryptography-layout:


Layout
------

``cryptography`` is broadly divided into two levels. One with safe
cryptographic recipes that require little to no configuration choices. These
are safe and easy to use and don't require developers to make many decisions.

The other level is low-level cryptographic primitives. These are often
dangerous and can be used incorrectly. They require making decisions and having
an in-depth knowledge of the cryptographic concepts at work. Because of the
potential danger in working at this level, this is referred to as the
"hazardous materials" or "hazmat" layer. These live in the
``cryptography.hazmat`` package, and their documentation will always contain an
admonition at the top.

We recommend using the recipes layer whenever possible, and falling back to the
hazmat layer only when necessary.

.. toctree::
    :maxdepth: 2
    :caption: The recipes layer

    fernet
    x509/index

.. toctree::
    :maxdepth: 2
    :caption: The hazardous materials layer

    hazmat/primitives/index
    exceptions
    random-numbers
    hazmat/backends/index
    hazmat/bindings/index

.. toctree::
    :maxdepth: 2
    :caption: The cryptography open source project

    installation
    changelog
    faq
    development/index
    security
    limitations
    api-stability
    doing-a-release
    community
    glossary


.. note::

    ``cryptography`` has not been subjected to an external audit of its code or
    documentation. If you're interested in discussing an audit please
    :doc:`get in touch </community>`.

.. _`Crypto 101, by Laurens Van Houtven`: https://www.crypto101.io/
