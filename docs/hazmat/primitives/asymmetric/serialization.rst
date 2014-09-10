.. hazmat::

Key Serialization
=================

.. currentmodule:: cryptography.hazmat.primitives.serialization

.. testsetup::

    pem_data = b"""
    -----BEGIN RSA PRIVATE KEY-----
    MIICXgIBAAKBgQDn09PV9KPE7Q+N5K5UtNLT1DLl8z/pKM2pP5tXqWx2OsEw00lC
    kDHdHESwzS050s/8rtkERKKyusCzCm9+vC1pQzUlmtibfF4PQAQc1pJL6KHqlidg
    Hw49atYmnC25CaeXt65pAYXoIacOZ8k5X7FW3Eagex8nG0iMw4ObOtg6CwIDAQAB
    AoGBAL31l/4YYN1rNrSZLrQgGyUSGsbLxJHEKolFon95R3O1fzoH117gkstQb4TE
    Cwv3jw/JIfBaYUq8tku/AE9D2Jx51x7kYaCuQIMTavKIgkXKfxTQCQDjSEfkvXMW
    4WOIj5sYdSCNbzLbaeFsWG32bSsBTy/sSheDIlCEFnqDuqwBAkEA+wYfJEMDf5nS
    VCQd9VKGM4HVeTWBioaWBFCflFdhc1Vb65dsNDp8iIMZgAHC2LEX5dMUmgqXk7AT
    lwFlIeW4CwJBAOxsSfuIVMuPKyx1xQ6ebpC7zeVxIOdswcM8ain91MSGDdKZw6pF
    ioFh3kUbKHw4yqqHbdRmUDAJ1mcgGJQOxgECQQCmQaGylKfmhWymyd0FtIip6J4I
    z4ViyEznwrZOu6kRiEF/QiUqWmpMx/fFrmTsvC5Fy43jkIxgBsiSxRvEXa+NAkB+
    5m0bhwTEslchKSGZhC6inzuYAQ4BSh4C1mXBnk5bIf0/Ymtk9KiwY8CzZS1o5+7Y
    c5LfI/+8mTss5UxsBDYBAkEA6NqhcsNWndIJZiWUU4u+RjFUQXqH8WCyJmEDCNxs
    7SGRS1DTUGX4Y70m9dQpguy6Zg+gpHC+o+ERZR06uEQr+w==
    -----END RSA PRIVATE KEY-----
    """.strip()
    message = b""

    def sign_with_rsa_key(key, message):
        return b""

    def sign_with_dsa_key(key, message):
        return b""

There are several common schemes for serializing asymmetric private and public
keys to bytes. They generally support encryption of private keys and additional
key metadata.

Many serialization formats support multiple different types of asymmetric keys
and will return an instance of the appropriate type. You should check that
the returned key matches the type your application expects when using these
methods.

    .. doctest::

        >>> from cryptography.hazmat.backends import default_backend
        >>> from cryptography.hazmat.primitives import interfaces
        >>> from cryptography.hazmat.primitives.serialization import load_pem_private_key
        >>> key = load_pem_private_key(pem_data, password=None, backend=default_backend())
        >>> if isinstance(key, interfaces.RSAPrivateKey):
        ...     signature = sign_with_rsa_key(key, message)
        ... elif isinstance(key, interfaces.DSAPrivateKey):
        ...     signature = sign_with_dsa_key(key, message)
        ... else:
        ...     raise TypeError

PEM
~~~

PEM is an encapsulation format, meaning keys in it can actually be any of
several different key types. However these are all self-identifying, so you
don't need to worry about this detail. PEM keys are recognizable because they
all begin with ``-----BEGIN {format}-----`` and end with ``-----END
{format}-----``.

.. function:: load_pem_private_key(data, password, backend):

    .. versionadded:: 0.6

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


PKCS #8 Format
~~~~~~~~~~~~~~

PKCS #8 is a serialization format originally standardized by RSA and currently
maintained by the IETF in :rfc:`5208` and :rfc:`5958`. It supports password
based encryption and additional key metadata attributes. These keys are
recognizable because they all begin with ``-----BEGIN PRIVATE KEY-----`` or
with ``-----BEGIN ENCRYPTED PRIVATE KEY-----`` if they have a password.


.. function:: load_pem_pkcs8_private_key(data, password, backend)

    .. versionadded:: 0.5

    Deserialize a private key from PEM encoded data to one of the supported
    asymmetric private key types.

    This has been deprecated in favor of :func:`load_pem_private_key`.

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

    This has been deprecated in favor of :func:`load_pem_private_key`.

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
