Welcome to ``cryptography``
===========================

.. warning::

    ``cryptography`` is very young, and very incomplete.

``cryptography`` is a Python library which exposes cryptographic recipes and
primitives.

Why a new crypto library for Python?
------------------------------------

We wanted to address a few issues with existing cryptography libraries in
Python:

* Lack of PyPy and Python 3 support.
* Lack of maintenance.
* Use of poor implementations of algorithms (i.e. ones with known side-channel
  attacks).
* Lack of high level, "Cryptography for humans", APIs.
* Absence of algorithms such as AES-GCM.
* Poor introspectability, and thus poor testability.
* Extremely error prone APIs, and bad defaults.


Contents
--------

.. toctree::
    :maxdepth: 2

    architecture
    exceptions
    glossary
    contributing
    security
    community

Hazardous Materials
-------------------

.. toctree::
    :maxdepth: 2

    hazmat/primitives/index
    hazmat/bindings/index
