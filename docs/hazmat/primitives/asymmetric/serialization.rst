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
        >>> from cryptography.hazmat.primitives.asymmetric import rsa
        >>> from cryptography.hazmat.primitives.serialization import load_pem_private_key
        >>> key = load_pem_private_key(pem_data, password=None, backend=default_backend())
        >>> if isinstance(key, rsa.RSAPrivateKey):
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

.. function:: load_pem_private_key(data, password, backend)

    .. versionadded:: 0.6

    Deserialize a private key from PEM encoded data to one of the supported
    asymmetric private key types.

    :param bytes data: The PEM encoded key data.

    :param bytes password: The password to use to decrypt the data. Should
        be ``None`` if the private key is not encrypted.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.PEMSerializationBackend`
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

.. function:: load_pem_public_key(data, backend)

    .. versionadded:: 0.6

    Deserialize a public key from PEM encoded data to one of the supported
    asymmetric public key types.

    :param bytes data: The PEM encoded key data.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.PEMSerializationBackend`
        provider.

    :returns: A new instance of a public key.

    :raises ValueError: If the PEM data's structure could not be decoded
        successfully.

    :raises UnsupportedAlgorithm: If the serialized key is of a type that
        is not supported by the backend.


OpenSSH Public Key
~~~~~~~~~~~~~~~~~~

The format used by OpenSSH to store public keys, as specified in :rfc:`4253`.

An example RSA key in OpenSSH format (line breaks added for formatting
purposes)::

    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDu/XRP1kyK6Cgt36gts9XAk
    FiiuJLW6RU0j3KKVZSs1I7Z3UmU9/9aVh/rZV43WQG8jaR6kkcP4stOR0DEtll
    PDA7ZRBnrfiHpSQYQ874AZaAoIjgkv7DBfsE6gcDQLub0PFjWyrYQUJhtOLQEK
    vY/G0vt2iRL3juawWmCFdTK3W3XvwAdgGk71i6lHt+deOPNEPN2H58E4odrZ2f
    sxn/adpDqfb2sM0kPwQs0aWvrrKGvUaustkivQE4XWiSFnB0oJB/lKK/CKVKuy
    ///ImSCGHQRvhwariN2tvZ6CBNSLh3iQgeB0AkyJlng7MXB2qYq/Ci2FUOryCX
    2MzHvnbv testkey@localhost

DSA keys look almost identical but begin with ``ssh-dss`` rather than
``ssh-rsa``. ECDSA keys have a slightly different format, they begin with
``ecdsa-sha2-{curve}``.

.. function:: load_ssh_public_key(data, backend)

    .. versionadded:: 0.7

    Deserialize a public key from OpenSSH (:rfc:`4253`) encoded data to an
    instance of the public key type for the specified backend.

    .. note::

        Currently Ed25519 keys are not supported.

    :param bytes data: The OpenSSH encoded key data.

    :param backend: A backend providing
        :class:`~cryptography.hazmat.backends.interfaces.RSABackend`,
        :class:`~cryptography.hazmat.backends.interfaces.DSABackend`, or
        :class:`~cryptography.hazmat.backends.interfaces.EllipticCurveBackend`
        depending on the key's type.

    :returns: A new instance of a public key type.

    :raises ValueError: If the OpenSSH data could not be properly decoded or
        if the key is not in the proper format.

    :raises UnsupportedAlgorithm: If the serialized key is of a type that is
        not supported.
