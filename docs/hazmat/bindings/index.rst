.. hazmat::

Bindings
========

.. module:: cryptography.hazmat.bindings

``cryptography`` aims to provide low-level CFFI based bindings to multiple
native C libraries. These provide no automatic initialization of the library
and may not provide complete wrappers for its API.

Using these functions directly is likely to require you to be careful in
managing memory allocation, locking and other resources.


Individual bindings
-------------------

.. toctree::
    :maxdepth: 1

    openssl
