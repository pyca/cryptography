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

    parameters_pem_data = b"""
    -----BEGIN DH PARAMETERS-----
    MIGHAoGBALsrWt44U1ojqTy88o0wfjysBE51V6Vtarjm2+5BslQK/RtlndHde3gx
    +ccNs+InANszcuJFI8AHt4743kGRzy5XSlul4q4dDJENOHoyqYxueFuFVJELEwLQ
    XrX/McKw+hS6GPVQnw6tZhgGo9apdNdYgeLQeQded8Bum8jqzP3rAgEC
    -----END DH PARAMETERS-----
    """.strip()

    parameters_der_data = base64.b64decode(
        b"MIGHAoGBALsrWt44U1ojqTy88o0wfjysBE51V6Vtarjm2+5BslQK/RtlndHde3gx+ccNs+In"
        b"ANsz\ncuJFI8AHt4743kGRzy5XSlul4q4dDJENOHoyqYxueFuFVJELEwLQXrX/McKw+hS6GP"
        b"VQnw6tZhgG\no9apdNdYgeLQeQded8Bum8jqzP3rAgEC"
    )

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

Key dumping
~~~~~~~~~~~

The ``serialization`` module contains functions for loading keys from
``bytes``. To dump a ``key`` object to ``bytes``, you must call the appropriate
method on the key object. Documentation for these methods in found in the
:mod:`~cryptography.hazmat.primitives.asymmetric.rsa`,
:mod:`~cryptography.hazmat.primitives.asymmetric.dsa`, and
:mod:`~cryptography.hazmat.primitives.asymmetric.ec` module documentation.

PEM
~~~

PEM is an encapsulation format, meaning keys in it can actually be any of
several different key types. However these are all self-identifying, so you
don't need to worry about this detail. PEM keys are recognizable because they
all begin with ``-----BEGIN {format}-----`` and end with ``-----END
{format}-----``.

.. note::

    A PEM block which starts with ``-----BEGIN CERTIFICATE-----`` is not a
    public or private key, it's an :doc:`X.509 Certificate </x509/index>`. You
    can load it using :func:`~cryptography.x509.load_pem_x509_certificate` and
    extract the public key with
    :meth:`Certificate.public_key <cryptography.x509.Certificate.public_key>`.

.. function:: load_pem_private_key(data, password, backend)

    .. versionadded:: 0.6

    Deserialize a private key from PEM encoded data to one of the supported
    asymmetric private key types.

    :param bytes data: The PEM encoded key data.

    :param bytes password: The password to use to decrypt the data. Should
        be ``None`` if the private key is not encrypted.

    :param backend: An instance of
        :class:`~cryptography.hazmat.backends.interfaces.PEMSerializationBackend`.

    :returns: One of
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`,
        or
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
        depending on the contents of ``data``.

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
    asymmetric public key types. The PEM encoded data is typically a
    ``subjectPublicKeyInfo`` payload as specified in :rfc:`5280`.

    .. doctest::

        >>> from cryptography.hazmat.primitives.serialization import load_pem_public_key
        >>> key = load_pem_public_key(public_pem_data, backend=default_backend())
        >>> isinstance(key, rsa.RSAPublicKey)
        True

    :param bytes data: The PEM encoded key data.

    :param backend: An instance of
        :class:`~cryptography.hazmat.backends.interfaces.PEMSerializationBackend`.


    :returns: One of
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`,
        or
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
        depending on the contents of ``data``.

    :raises ValueError: If the PEM data's structure could not be decoded
        successfully.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized key
        is of a type that is not supported by the backend.

.. function:: load_pem_parameters(data, backend)

    .. versionadded:: 2.0

    Deserialize parameters from PEM encoded data to one of the supported
    asymmetric parameters types.

    .. doctest::

        >>> from cryptography.hazmat.primitives.serialization import load_pem_parameters
        >>> from cryptography.hazmat.primitives.asymmetric import dh
        >>> parameters = load_pem_parameters(parameters_pem_data, backend=default_backend())
        >>> isinstance(parameters, dh.DHParameters)
        True

    :param bytes data: The PEM encoded parameters data.

    :param backend: An instance of
        :class:`~cryptography.hazmat.backends.interfaces.PEMSerializationBackend`.


    :returns: Currently only
        :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`
        supported.

    :raises ValueError: If the PEM data's structure could not be decoded
        successfully.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized parameters
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

    :param backend: An instance of
        :class:`~cryptography.hazmat.backends.interfaces.DERSerializationBackend`.

    :returns: One of
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`,
        or
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
        depending on the contents of ``data``.

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
    asymmetric public key types. The DER encoded data is typically a
    ``subjectPublicKeyInfo`` payload as specified in :rfc:`5280`.

    :param bytes data: The DER encoded key data.

    :param backend: An instance of
        :class:`~cryptography.hazmat.backends.interfaces.DERSerializationBackend`.

    :returns: One of
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`,
        or
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
        depending on the contents of ``data``.

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

.. function:: load_der_parameters(data, backend)

    .. versionadded:: 2.0

    Deserialize parameters from DER encoded data to one of the supported
    asymmetric parameters types.

    :param bytes data: The DER encoded parameters data.

    :param backend: An instance of
        :class:`~cryptography.hazmat.backends.interfaces.DERSerializationBackend`.

    :returns: Currently only
        :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`
        supported.

    :raises ValueError: If the DER data's structure could not be decoded
        successfully.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized key is of a type that
        is not supported by the backend.

    .. doctest::

        >>> from cryptography.hazmat.backends import default_backend
        >>> from cryptography.hazmat.primitives.asymmetric import dh
        >>> from cryptography.hazmat.primitives.serialization import load_der_parameters
        >>> parameters = load_der_parameters(parameters_der_data, backend=default_backend())
        >>> isinstance(parameters, dh.DHParameters)
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

    :param backend: A backend which implements
        :class:`~cryptography.hazmat.backends.interfaces.RSABackend`,
        :class:`~cryptography.hazmat.backends.interfaces.DSABackend`, or
        :class:`~cryptography.hazmat.backends.interfaces.EllipticCurveBackend`
        depending on the key's type.

    :returns: One of
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
        or
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
        depending on the contents of ``data``.

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
    ,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization`
    , :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKeyWithSerialization`
    and
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization`.

    .. attribute:: TraditionalOpenSSL

        Frequently known as PKCS#1 format. Still a widely used format, but
        generally considered legacy.

    .. attribute:: PKCS8

        A more modern format for serializing keys which allows for better
        encryption. Choose this unless you have explicit legacy compatibility
        requirements.

.. class:: PublicFormat

    .. versionadded:: 0.8

    An enumeration for public key formats. Used with the ``public_bytes``
    method available on
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization`
    ,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization`
    , :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKeyWithSerialization`
    , and
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithSerialization`.

    .. attribute:: SubjectPublicKeyInfo

        This is the typical public key format. It consists of an algorithm
        identifier and the public key as a bit string. Choose this unless
        you have specific needs.

    .. attribute:: PKCS1

        Just the public key elements (without the algorithm identifier). This
        format is RSA only, but is used by some older systems.

    .. attribute:: OpenSSH

        .. versionadded:: 1.4

        The public key format used by OpenSSH (e.g. as found in
        ``~/.ssh/id_rsa.pub`` or ``~/.ssh/authorized_keys``).

.. class:: ParameterFormat

    .. versionadded:: 2.0

    An enumeration for parameters formats. Used with the ``parameter_bytes``
    method available on
    :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParametersWithSerialization`.

    .. attribute:: PKCS3

        ASN1 DH parameters sequence as defined in `PKCS3`_.

Serialization Encodings
~~~~~~~~~~~~~~~~~~~~~~~

.. class:: Encoding

    An enumeration for encoding types. Used with the ``private_bytes`` method
    available on
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`
    ,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization`
    , :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKeyWithSerialization`
    and
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization`
    as well as ``public_bytes`` on
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization`,
    :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKeyWithSerialization`
    and
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization`.

    .. attribute:: PEM

        .. versionadded:: 0.8

        For PEM format. This is a base64 format with delimiters.

    .. attribute:: DER

        .. versionadded:: 0.9

        For DER format. This is a binary format.

    .. attribute:: OpenSSH

        .. versionadded:: 1.4

        The format used by OpenSSH public keys. This is a text format.


Serialization Encryption Types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: KeySerializationEncryption

    Objects with this interface are usable as encryption types with methods
    like ``private_bytes`` available on
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`
    ,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization`
    , :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKeyWithSerialization`
    and
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization`.
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


.. _`PKCS3`: https://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-3-diffie-hellman-key-agreement-standar.htm
