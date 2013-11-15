.. hazmat::

Backend Interfaces
==================

.. currentmodule:: cryptography.hazmat.bindings.interfaces


.. class:: CipherBackend

    .. method:: cipher_supported(cipher, mode)

        pass

    .. method:: register_cipher_adapter(cipher_cls, mode_cls, adapter)

        pass

    .. method:: create_symmetric_encryption_ctx(cipher, mode)

        pass

    .. method:: create_symmetric_decryption_ctx(cipher, mode)

        pass


.. class:: HashBackend

    .. method:: hash_supported(algorithm)

        pass

    .. method:: create_hash_ctx(algorithm)

        pass


.. class:: HMACBackend

    .. method:: create_hmac_ctx(algorithm)

        pass
