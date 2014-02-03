.. hazmat::

MultiBackend
============

.. currentmodule:: cryptography.hazmat.backends.multibackend

.. class:: MultiBackend(backends)

    This class allows you to combine multiple backends into a single backend
    which offers the combined features of all of its constituents.

    :param backends: A ``list`` of backend objects. Backends are checked for
                     feature support in the other they exist in this list.
