Welcome to ``cryptography``
===========================

``cryptography`` is a Python library which exposes cryptographic recipes and
primitives. Our goal is for it to be your "cryptographic standard library". If
you are interested in learning more about the field of cryptography, we
recommend `Crypto 101, by Laurens Van Houtven`_.

Installation
------------
You can install ``cryptography`` with ``pip``:

.. code-block:: console

    $ pip install cryptography

See :doc:`Installation <installation>` for more information.

Why a new crypto library for Python?
------------------------------------

If you've done cryptographic work in Python before, you've probably seen some
other libraries in Python, such as *M2Crypto*, *PyCrypto*, or *PyOpenSSL*. In
building ``cryptography`` we wanted to address a few issues we observed in the
existing libraries:

* Lack of PyPy and Python 3 support.
* Lack of maintenance.
* Use of poor implementations of algorithms (i.e. ones with known side-channel
  attacks).
* Lack of high level, "Cryptography for humans", APIs.
* Absence of algorithms such as
  :class:`AES-GCM <cryptography.hazmat.primitives.ciphers.modes.GCM>` and
  :class:`~cryptography.hazmat.primitives.kdf.hkdf.HKDF`.
* Poor introspectability, and thus poor testability.
* Extremely error prone APIs, and bad defaults.


.. _cryptography-layout:

Layout
------

``cryptography`` is broadly divided into two levels. One with safe
cryptographic recipes, "cryptography for humans" if you will. These are safe
and easy to use and don't require developers to make many decisions.

The other level is low-level cryptographic primitives. These are often
dangerous and can be used incorrectly. They require making decisions and having
an in-depth knowledge of the cryptographic concepts at work. Because of the
potential danger in working at this level, this is referred to as the
"hazardous materials" or "hazmat" layer. These live in the
``cryptography.hazmat`` package, and their documentation will always contain an
admonition at the top.

We recommend using the recipes layer whenever possible, and falling back to the
hazmat layer only when necessary.

The recipes layer
~~~~~~~~~~~~~~~~~

.. toctree::
    :maxdepth: 2

    fernet
    random-numbers
    exceptions
    faq
    glossary
    x509

The hazardous materials layer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. toctree::
    :maxdepth: 2

    hazmat/primitives/index
    hazmat/backends/index
    hazmat/bindings/index

The ``cryptography`` open source project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. toctree::
    :maxdepth: 2

    installation
    development/index
    security
    limitations
    api-stability
    doing-a-release
    changelog
    community


.. note::

    ``cryptography`` has not been subjected to an external audit of its code or
    documentation. If you're interested in discussing an audit please
    :doc:`get in touch </community>`.

.. _`Crypto 101, by Laurens Van Houtven`: https://www.crypto101.io/
