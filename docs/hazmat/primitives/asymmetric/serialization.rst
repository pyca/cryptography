.. hazmat::

Key Serialization
=================

.. currentmodule:: cryptography.hazmat.primitives.serialization

There are several common schemes for serializing asymmetric private and public
keys to bytes. They generally support encryption of private keys and additional
key metadata.


.. class:: TraditionalOpenSSLPrivateKey(private_key)

    .. versionadded:: 0.4

    The "traditional" PKCS #1 based serialization format used by OpenSSL.
    It supports password based symmetric key encryption. Commonly found in
    OpenSSL based TLS applications. It is usually found in PEM format with a
    header that mentions the type of the serialized key. e.g.
    ``-----BEGIN RSA PRIVATE KEY-----``.

    .. classmethod:: load_pem(data, password, backend)

        Construct a new instance from PEM encoded private key data.

        :param bytes data: The PEM encoded key data.

        :param bytes password: The password to use to decrypt the data. Should
                               be ``None`` if the private key is not encrypted.
        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.TraditionalOpenSSLSerializationBackend`
            provider.

        :returns: A new instance of ``TraditionalOpenSSLPrivateKey``.

        :raises ValueError: If the PEM data could not be decrypted or if its
                            structure could not be decoded successfully.

        :raises TypeError: If a ``password`` was given and the private key was
                           not encrypted. Or if the key was encrypted but no
                           password was supplied.

        :raises UnsupportedAlgorithm: If the serialized key is of a type that
                                      is not supported by the backend or if the
                                      key is encrypted with a symmetric cipher
                                      that is not supported by the backend.

    .. attribute:: private_key

        The deserialized private key object. An instance of any of the private
        key types supported by ``cryptography``. If you wish to support
        loading multiple types of asymmetric key in your application you will
        need to check the type of the key and act accordingly. For example

        .. code-block:: pycon

            >>> key = TraditionalOpenSSLPrivateKey.load_pem(pem_data, None, backend)
            >>> if isinstance(key, rsa.RSAPrivateKey):
            >>>     signature = sign_with_rsa_key(key, message)
            >>> elif isinstance(key, dsa.DSAPrivateKey):
            >>>     signature = sign_with_dsa_key(key, message)
            >>> else:
            >>>     raise TypeError
