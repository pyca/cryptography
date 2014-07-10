.. hazmat::

Key Serialization
=================

.. currentmodule:: cryptography.hazmat.primitives.serialization

There are several common schemes for serializing asymmetric private and public
keys to bytes. They generally support encryption of private keys and additional
key metadata.

Many serialization formats support multiple different types of asymmetric keys
and will return an instance of the appropriate type. You should check that
the returned key matches the type your application expects when using these
methods.

    .. code-block:: pycon

        >>> key = load_pkcs8_private_key(pem_data, None, backend)
        >>> if isinstance(key, rsa.RSAPrivateKey):
        >>>     signature = sign_with_rsa_key(key, message)
        >>> elif isinstance(key, dsa.DSAPrivateKey):
        >>>     signature = sign_with_dsa_key(key, message)
        >>> else:
        >>>     raise TypeError


PKCS #8 Format
~~~~~~~~~~~~~~

PKCS #8 is a serialization format originally standardized by RSA and currently
maintained by the IETF in :rfc:`5208` and :rfc:`5958`. It supports password
based encryption and additional key metadata attributes. These keys are
recognizable because they all begin with ``-----BEGIN PRIVATE KEY-----`` or
with ``-----BEGIN ENCRYPTED PRIVATE KEY-----`` if they have a password.


.. function:: load_pkcs8_private_key(data, password, backend)

    .. versionadded:: 0.5

    Deserialize a private key from PEM encoded data to one of the supported
    asymmetric private key types.

    :param bytes data: The PEM encoded key data.

    :param bytes password: The password to use to decrypt the data. Should
        be ``None`` if the private key is not encrypted.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.PKCS8SerializationBackend`
        provider.

    :returns: A new instance of a private key.

    :raises ValueError: If the PEM data could not be decrypted or if its
        structure could not be decoded successfully.

    :raises TypeError: If a ``password`` was given and the private key was
        not encrypted. Or if the key was encrypted but no
        password was supplied.

    :raises UnsupportedAlgorithm: If the serialized key is of a type that
        is not supported by the backend or if the key is encrypted with a
        symmetric cipher that is not supported by the backend.


Traditional OpenSSL Format
~~~~~~~~~~~~~~~~~~~~~~~~~~

The "traditional" PKCS #1 based serialization format used by OpenSSL. It
supports password based symmetric key encryption. Commonly found in OpenSSL
based TLS applications. It is usually found in PEM format with a header that
mentions the type of the serialized key. e.g. ``-----BEGIN RSA PRIVATE
KEY-----`` or ``-----BEGIN DSA PRIVATE KEY-----``.

.. function:: load_pem_traditional_openssl_private_key(data, password, backend)

    .. versionadded:: 0.5

    Deserialize a private key from PEM encoded data to one of the supported
    asymmetric private key types.

    :param bytes data: The PEM encoded key data.

    :param bytes password: The password to use to decrypt the data. Should
        be ``None`` if the private key is not encrypted.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.TraditionalOpenSSLSerializationBackend`
        provider.

    :returns: A new instance of a private key.

    :raises ValueError: If the PEM data could not be decrypted or if its
        structure could not be decoded successfully.

    :raises TypeError: If a ``password`` was given and the private key was
        not encrypted. Or if the key was encrypted but no
        password was supplied.

    :raises UnsupportedAlgorithm: If the serialized key is of a type that
        is not supported by the backend or if the key is encrypted with a
        symmetric cipher that is not supported by the backend.
