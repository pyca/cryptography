.. hazmat::

Backends
========

Getting a backend
-----------------

.. currentmodule:: cryptography.hazmat.backends

``cryptography`` was designed to support multiple cryptographic backends, but
consumers rarely need this flexibility. Starting with version 3.1 ``backend``
arguments are optional and the default backend will automatically be selected
if none is specified.

On older versions you can get the default backend by calling
:func:`~default_backend`.


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
