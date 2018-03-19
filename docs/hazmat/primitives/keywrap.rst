.. hazmat::

.. module:: cryptography.hazmat.primitives.keywrap

Key wrapping
============

Key wrapping is a cryptographic construct that uses symmetric encryption to
encapsulate key material. Key wrapping algorithms are occasionally utilized
to protect keys at rest or transmit them over insecure networks. Many of the
protections offered by key wrapping are also offered by using authenticated
:doc:`symmetric encryption </hazmat/primitives/symmetric-encryption>`.

.. function:: aes_key_wrap(wrapping_key, key_to_wrap, backend)

    .. versionadded:: 1.1

    This function performs AES key wrap (without padding) as specified in
    :rfc:`3394`.

    :param bytes wrapping_key: The wrapping key.

    :param bytes key_to_wrap: The key to wrap.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`
        instance that supports
        :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES`.

    :return bytes: The wrapped key as bytes.

.. function:: aes_key_unwrap(wrapping_key, wrapped_key, backend)

    .. versionadded:: 1.1

    This function performs AES key unwrap (without padding) as specified in
    :rfc:`3394`.

    :param bytes wrapping_key: The wrapping key.

    :param bytes wrapped_key: The wrapped key.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`
        instance that supports
        :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES`.

    :return bytes: The unwrapped key as bytes.

    :raises cryptography.hazmat.primitives.keywrap.InvalidUnwrap: This is
        raised if the key is not successfully unwrapped.

.. function:: aes_key_wrap_with_padding(wrapping_key, key_to_wrap, backend)

    .. versionadded:: 2.2

    This function performs AES key wrap with padding as specified in
    :rfc:`5649`.

    :param bytes wrapping_key: The wrapping key.

    :param bytes key_to_wrap: The key to wrap.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`
        instance that supports
        :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES`.

    :return bytes: The wrapped key as bytes.

.. function:: aes_key_unwrap_with_padding(wrapping_key, wrapped_key, backend)

    .. versionadded:: 2.2

    This function performs AES key unwrap with padding as specified in
    :rfc:`5649`.

    :param bytes wrapping_key: The wrapping key.

    :param bytes wrapped_key: The wrapped key.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`
        instance that supports
        :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES`.

    :return bytes: The unwrapped key as bytes.

    :raises cryptography.hazmat.primitives.keywrap.InvalidUnwrap: This is
        raised if the key is not successfully unwrapped.

Exceptions
~~~~~~~~~~

.. class:: InvalidUnwrap

    This is raised when a wrapped key fails to unwrap. It can be caused by a
    corrupted or invalid wrapped key or an invalid wrapping key.
