.. hazmat::

Backend Interfaces
==================

.. currentmodule:: cryptography.hazmat.bindings.interfaces


Backend implementations may provide a number of interfaces to support operations
such as :doc:`/hazmat/primitives/symmetric-encryption`,
:doc:`/hazmat/primitives/cryptographic-hashes`, and
:doc:`/hazmat/primitives/hmac`.

A specific ``backend`` may provide one or more of these interfaces.


.. class:: CipherBackend

    A backend which provides methods for using ciphers for encryption
    and decryption.

    .. method:: cipher_supported(cipher, mode)

        Check if a ``cipher`` and ``mode`` combination is supported by
        this backend.

        :param cipher: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.CipherAlgorithm`
            provider.
        :param mode: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.Mode` provider.

        :returns: ``True`` if the specified ``cipher`` and ``mode`` combination
            is supported by this backend, otherwise ``False``

    .. method:: register_cipher_adapter(cipher_cls, mode_cls, adapter)

        Register an adapter which can be used to create a backend specific
        object from instances of the
        :class:`~cryptography.hazmat.primitives.interfaces.CipherAlgorithm` and
        the :class:`~cryptography.hazmat.primitives.interfaces.Mode` primitives.

        :param cipher_cls: A class whose instances provide
            :class:`~cryptography.hazmat.primitives.interfaces.CipherAlgorithm`
        :param mode_cls: A class whose instances provide:
            :class:`~cryptography.hazmat.primitives.interfaces.Mode`
        :param adapter: A ``function`` that takes 3 arguments, ``backend`` (a
            :class:`CipherBackend` provider), ``cipher`` (a
            :class:`~cryptography.hazmat.primitives.interfaces.CipherAlgorithm`
            provider ), and ``mode`` (a
            :class:`~cryptography.hazmat.primitives.interfaces.Mode` provider).
            It returns a backend specific object which may be used to construct
            a :class:`~cryptogrpahy.hazmat.primitives.interfaces.CipherContext`.


    .. method:: create_symmetric_encryption_ctx(cipher, mode)

        Create a
        :class:`~cryptogrpahy.hazmat.primitives.interfaces.CipherContext` that
        can be used for encrypting data with the symmetric ``cipher`` using
        the given ``mode``.

        :param cipher: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.CipherAlgorithm`
            provider.
        :param mode: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.Mode` provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.CipherContext`


    .. method:: create_symmetric_decryption_ctx(cipher, mode)

        Create a
        :class:`~cryptogrpahy.hazmat.primitives.interfaces.CipherContext` that
        can be used for decrypting data with the symmetric ``cipher`` using
        the given ``mode``.

        :param cipher: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.CipherAlgorithm`
            provider.
        :param mode: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.Mode` provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.CipherContext`


.. class:: HashBackend

    A backend with methods for using cryptographic hash functions.

    .. method:: hash_supported(algorithm)

        Check if the specified ``algorithm`` is supported by this backend.

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
            provider.

        :returns: ``True`` if the specified ``algorithm`` is supported by this
            backend, otherwise ``False``.


    .. method:: create_hash_ctx(algorithm)

        Create a
        :class:`~cryptogrpahy.hazmat.primitives.interfaces.HashContext` that
        uses the specified ``algorithm`` to calculate a message digest.

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.HashContext`


.. class:: HMACBackend

    A backend with methods for using cryptographic hash functions as message
    authentication codes.

    .. method:: create_hmac_ctx(algorithm)

        Create a
        :class:`~cryptogrpahy.hazmat.primitives.interfaces.HashContext` that
        uses the specified ``algorithm`` to calculate a hash-based message
        authentication code.

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.HashContext`
