Exceptions
==========

.. currentmodule:: cryptography.exceptions


.. class:: UnsupportedAlgorithm

    Raised when the requested algorithm, or combination of algorithms is not
    supported.


.. class:: AlreadyFinalized

    This is raised when a context is used after being finalized.


.. class:: InvalidSignature

    This is raised when signature verification fails. This can occur with
    HMAC or asymmetric key signature validation.


.. class:: NotYetFinalized

    This is raised when the AEAD tag property is accessed on a context
    before it is finalized.


.. class:: AlreadyUpdated

    This is raised when additional data is added to a context after update
    has already been called.


.. class:: InvalidKey

    This is raised when the verify method of a key derivation function's
    computed key does not match the expected key.
