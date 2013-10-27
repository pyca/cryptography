Architecture
============

.. warning::

    Because ``cryptography`` is so young, much of this document is
    aspirational, rather than documentation.

``cryptography`` has three different layers:

* ``cryptography.bindings``: This package contains bindings to low level
  cryptographic libraries. Our initial target will be OpenSSL.
* ``cryptography.hazmat.primitives``: This packages contains low level
  algorithms, things like ``AES`` or ``SHA1``. This is implemented on top of
  ``cryptography.bindings``.
* ``cryptography``: This package contains higher level recipes, for example
  "encrypt and then MAC". This is implemented on top of
  ``cryptography.hazmat.primitives``.
