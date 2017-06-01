.. hazmat::

Backends
========

Getting a backend
-----------------

.. currentmodule:: cryptography.hazmat.backends

``cryptography`` was originally designed to support multiple backends, but
this design has been deprecated.

You can get the default backend by calling :func:`~default_backend`.


.. function:: default_backend()

    :returns: An object that provides at least
        :class:`~interfaces.CipherBackend`, :class:`~interfaces.HashBackend`, and
        :class:`~interfaces.HMACBackend`.

Individual backends
-------------------

.. toctree::
    :maxdepth: 1

    openssl
    interfaces
