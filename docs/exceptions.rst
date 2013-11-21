Exceptions
==========

.. currentmodule:: cryptography.exceptions

.. class:: AlreadyFinalized

    This is raised when a context is used after being finalized.

.. class:: NotFinalized

    This is raised when the AEAD tag property is accessed on a context
    before it is finalized.


.. class:: UnsupportedAlgorithm

    This is raised when a backend doesn't support the requested algorithm (or
    combination of algorithms).
