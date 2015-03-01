.. hazmat::

Key Serialization
=================

.. module:: cryptography.hazmat.primitives.serialization

.. testsetup::

    import base64

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
    public_pem_data = b"""
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDn09PV9KPE7Q+N5K5UtNLT1DLl
    8z/pKM2pP5tXqWx2OsEw00lCkDHdHESwzS050s/8rtkERKKyusCzCm9+vC1pQzUl
    mtibfF4PQAQc1pJL6KHqlidgHw49atYmnC25CaeXt65pAYXoIacOZ8k5X7FW3Eag
    ex8nG0iMw4ObOtg6CwIDAQAB
    -----END PUBLIC KEY-----
    """.strip()
    der_data = base64.b64decode(
        b"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALskegl+DrI3Msw5Z63x"
        b"nj1rgoPR0KykwBi+jZgAwHv/B0TJyhy6NuEnaf+x442L7lepOqoWQzlUGXyuaSQU9mT/"
        b"vHTGZ2xM8QJJaccr4eGho0MU9HePyNCFWjWVrGKpwSEAd6CLlzC0Wiy4kC9IoAUoS/IP"
        b"jeyLTQNCddatgcARAgMBAAECgYAA/LlKJgeJUStTcpHgGD6mXjHvnAwWJELQKDP5+tA8"
        b"VAQGwBX1G5qzJDGrPGtHQ7DSqdwF4YFZtgTpZmGq1wsAjz3lv6L4XiVsHiIPtP1B4gMx"
        b"X9ogxcDzVQ7hyezXPioMAcp7Isus9Csn8HhftcL56BRabn6GvWqbIAy6zJcgEQJBAMlZ"
        b"nymKW5/jKth+wkCfqEXlPhGNPO1uq87QZUbYxwdjtSM09J9+HMfH+WXR9ARCOL46DJ0I"
        b"JfyjcdmuDDlh9IkCQQDt76up1Tmc7lkb/89IRBu2MudGJPMEf96VCG11nmcXulyk1OLi"
        b"TXfO62YpxZbgYrvlrNxEYlSG7WQMztBgA51JAkBU2RhyJ+S+drsaaigvlVgSxCyotszi"
        b"/Q0XZMgY18bfPUwanvkqsLkuEv3sw1HB7an9t3aTQdjIIpQad/acw8OJAkEAjvmnCK21"
        b"KgTbjQShtQYgNNLPwImxcjG4OYvP4o6l2k9FHlNCZsQwSymOwWkXKYyK5g+CaKFBs7Zw"
        b"mXWpJxjk6QJBAInqbm1w3yVfGD9I2mMQi/6oDJQP3pdWU4mU4h4sdDyRgTQLpkD4yypg"
        b"jOACt4mTzxifSVT9fT+a79SkT8FFmZE="
    )
    public_der_data = base64.b64decode(
        b"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7JHoJfg6yNzLMOWet8Z49a4KD0dCs"
        b"pMAYvo2YAMB7/wdEycocujbhJ2n/seONi+5XqTqqFkM5VBl8rmkkFPZk/7x0xmdsTPEC"
        b"SWnHK+HhoaNDFPR3j8jQhVo1laxiqcEhAHegi5cwtFosuJAvSKAFKEvyD43si00DQnXW"
        b"rYHAEQIDAQAB"
    )
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
        >>> from cryptography.hazmat.primitives.asymmetric import dsa, rsa
        >>> from cryptography.hazmat.primitives.serialization import load_pem_private_key
        >>> key = load_pem_private_key(pem_data, password=None, backend=default_backend())
        >>> if isinstance(key, rsa.RSAPrivateKey):
        ...     signature = sign_with_rsa_key(key, message)
        ... elif isinstance(key, dsa.DSAPrivateKey):
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

.. note::

    A PEM block which starts with ``-----BEGIN CERTIFICATE-----`` is not a
    public or private key, it's an :doc:`X.509 Certificate </x509>`. You can
    load it using :func:`~cryptography.x509.load_pem_x509_certificate` and
    extract the public key with
    :meth:`Certificate.public_key <cryptography.x509.Certificate.public_key>`.

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

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized key
        is of a type that is not supported by the backend or if the key is
        encrypted with a symmetric cipher that is not supported by the backend.

.. function:: load_pem_public_key(data, backend)

    .. versionadded:: 0.6

    Deserialize a public key from PEM encoded data to one of the supported
    asymmetric public key types.

    .. doctest::

        >>> from cryptography.hazmat.primitives.serialization import load_pem_public_key
        >>> key = load_pem_public_key(public_pem_data, backend=default_backend())
        >>> isinstance(key, rsa.RSAPublicKey)
        True

    :param bytes data: The PEM encoded key data.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.PEMSerializationBackend`
        provider.

    :returns: A new instance of a public key.

    :raises ValueError: If the PEM data's structure could not be decoded
        successfully.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized key
        is of a type that is not supported by the backend.

DER
~~~

DER is an ASN.1 encoding type. There are no encapsulation boundaries and the
data is binary. DER keys may be in a variety of formats, but as long as you
know whether it is a public or private key the loading functions will handle
the rest.

.. function:: load_der_private_key(data, password, backend)

    .. versionadded:: 0.8

    Deserialize a private key from DER encoded data to one of the supported
    asymmetric private key types.

    :param bytes data: The DER encoded key data.

    :param bytes password: The password to use to decrypt the data. Should
        be ``None`` if the private key is not encrypted.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.DERSerializationBackend`
        provider.

    :returns: A new instance of a private key.

    :raises ValueError: If the DER data could not be decrypted or if its
        structure could not be decoded successfully.

    :raises TypeError: If a ``password`` was given and the private key was
        not encrypted. Or if the key was encrypted but no
        password was supplied.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized key is of a type that
        is not supported by the backend or if the key is encrypted with a
        symmetric cipher that is not supported by the backend.

    .. doctest::

        >>> from cryptography.hazmat.backends import default_backend
        >>> from cryptography.hazmat.primitives.asymmetric import rsa
        >>> from cryptography.hazmat.primitives.serialization import load_der_private_key
        >>> key = load_der_private_key(der_data, password=None, backend=default_backend())
        >>> isinstance(key, rsa.RSAPrivateKey)
        True

.. function:: load_der_public_key(data, backend)

    .. versionadded:: 0.8

    Deserialize a public key from DER encoded data to one of the supported
    asymmetric public key types.

    :param bytes data: The DER encoded key data.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.DERSerializationBackend`
        provider.

    :returns: A new instance of a public key.

    :raises ValueError: If the DER data's structure could not be decoded
        successfully.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized key is of a type that
        is not supported by the backend.

    .. doctest::

        >>> from cryptography.hazmat.backends import default_backend
        >>> from cryptography.hazmat.primitives.asymmetric import rsa
        >>> from cryptography.hazmat.primitives.serialization import load_der_public_key
        >>> key = load_der_public_key(public_der_data, backend=default_backend())
        >>> isinstance(key, rsa.RSAPublicKey)
        True


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

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized
        key is of a type that is not supported.

Serialization Formats
~~~~~~~~~~~~~~~~~~~~~

.. class:: PrivateFormat

    .. versionadded:: 0.8

    An enumeration for private key formats. Used with the ``private_bytes``
    method available on
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`
    and
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization`.

    .. attribute:: TraditionalOpenSSL

        Frequently known as PKCS#1 format. Still a widely used format, but
        generally considered legacy.

    .. attribute:: PKCS8

        A more modern format for serializing keys which allows for better
        encryption. Choose this unless you have explicit legacy compatibility
        requirements.

Serialization Encodings
~~~~~~~~~~~~~~~~~~~~~~~

.. class:: Encoding

    .. versionadded:: 0.8

    An enumeration for encoding types. Used with the ``private_bytes`` method
    available on
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`
    and
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization`.

    .. attribute:: PEM

        For PEM format. This is a base64 format with delimiters.

    .. attribute:: DER

        For DER format. This is a binary format.


Serialization Encryption Types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: KeySerializationEncryption

    Objects with this interface are usable as encryption types with methods
    like ``private_bytes`` available on
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`
    and
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization`.
    All other classes in this section represent the available choices for
    encryption and have this interface. They are used with
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.private_bytes`.

.. class:: BestAvailableEncryption(password)

    Encrypt using the best available encryption for a given key's backend.
    This is a curated encryption choice and the algorithm may change over
    time.

    :param bytes password: The password to use for encryption.

.. class:: NoEncryption

    Do not encrypt.
