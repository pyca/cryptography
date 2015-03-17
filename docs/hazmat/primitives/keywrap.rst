.. hazmat::

.. module:: cryptography.hazmat.primitives.keywrap

Key wrapping
============

Key wrapping is a cryptographic construct that uses symmetric encryption to
encapsulate key material.

.. function:: aes_key_wrap(wrapping_key, key_to_wrap, backend)

    :param bytes wrapping_key: The wrapping key.

    :param bytes key_to_wrap: The key to wrap.

    :param backend: An
        :class:`~cryptography.hazmat.backends.interfaces.AESKeyWrapBackend`
        provider.

    :return bytes: The wrapped key as bytes.

.. function:: aes_key_unwrap(wrapping_key, wrapped_key, backend)

    :param bytes wrapping_key: The wrapping key.

    :param bytes wrapped_key: The wrapped key.

    :param backend: An
        :class:`~cryptography.hazmat.backends.interfaces.AESKeyWrapBackend`
        provider.

    :return bytes: The unwrapped key as bytes.

Exceptions
~~~~~~~~~~

.. class:: InvalidUnwrap

    This is raised when a wrapped key fails to unwrap. It can be caused by a
    corrupted or invalid wrapped key or an invalid wrapping key.
