Welcome to ``cryptography``
===========================

``cryptography`` is a Python library which exposes cryptographic recipes and
primitives. We hope it'll be your one-stop-shop for all your cryptographic
needs in Python.

Installing
----------

We don't yet have a release on PyPI, for now you can install ``cryptography``
directly from Github:

.. code-block:: console

    $ pip install git+https://github.com/pyca/cryptography

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
* Absence of algorithms such as AES-GCM.
* Poor introspectability, and thus poor testability.
* Extremely error prone APIs, and bad defaults.

Layout
------

``cryptography`` is broadly divided into two levels. One with safe
cryptographic recipes, "cryptography for humans" if you will. These are safe
and easy to use and don't require developers to make many decisions.

The other level is low-level cryptographic primitives. These are often
dangerous and can be used incorrectly. They require making decisions and having
an in-depth knowledge of the cryptographic concepts at work. Because of the
potential danger in working at this level, this is referred to as the
"hazardous materials" or "hazmat" layer.

We recommend using the recipes layer whenever possible, and falling back to the
hazmat layer only when necessary.

The recipes layer
~~~~~~~~~~~~~~~~~

.. toctree::
    :maxdepth: 2

    fernet
    architecture
    exceptions
    glossary

The hazardous materials layer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. toctree::
    :maxdepth: 2

    hazmat/primitives/index
    hazmat/backends/index

The ``cryptography`` open source project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. toctree::
    :maxdepth: 2

    contributing
    security
    api-stability
    community
