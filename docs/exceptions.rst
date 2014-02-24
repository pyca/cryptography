Exceptions
==========

.. currentmodule:: cryptography.exceptions

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


.. class:: UnsupportedAlgorithm

    This is raised when a backend doesn't support the requested algorithm (or
    combination of algorithms).


.. class:: InvalidKey

    This is raised when the verify method of a key derivation function's
    computed key does not match the expected key.


.. class:: InvalidToken

    This is raised when the verify method of a one time password function's
    computed token does not match the expected token.


.. class:: UnsupportedPadding

    This is raised when the chosen padding is not supported by the backend.
