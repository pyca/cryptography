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

        >>> from cryptography.hazmat.primitives.asymmetric import dsa, rsa
        >>> from cryptography.hazmat.primitives.serialization import load_pem_private_key
        >>> key = load_pem_private_key(pem_data, password=None)
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

.. function:: load_pem_private_key(data, password, backend=None)

    .. versionadded:: 0.6

    Deserialize a private key from PEM encoded data to one of the supported
    asymmetric private key types.

    :param data: The PEM encoded key data.
    :type data: :term:`bytes-like`

    :param password: The password to use to decrypt the data. Should
        be ``None`` if the private key is not encrypted.
    :type data: :term:`bytes-like`

    :param backend: An optional instance of
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
        is of a type that is not supported by the backend.

.. function:: load_pem_public_key(data, backend=None)

    .. versionadded:: 0.6

    Deserialize a public key from PEM encoded data to one of the supported
    asymmetric public key types. The PEM encoded data is typically a
    ``subjectPublicKeyInfo`` payload as specified in :rfc:`5280`.

    .. doctest::

        >>> from cryptography.hazmat.primitives.serialization import load_pem_public_key
        >>> key = load_pem_public_key(public_pem_data)
        >>> isinstance(key, rsa.RSAPublicKey)
        True

    :param bytes data: The PEM encoded key data.

    :param backend: An optional instance of
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

.. function:: load_pem_parameters(data, backend=None)

    .. versionadded:: 2.0

    Deserialize parameters from PEM encoded data to one of the supported
    asymmetric parameters types.

    .. doctest::

        >>> from cryptography.hazmat.primitives.serialization import load_pem_parameters
        >>> from cryptography.hazmat.primitives.asymmetric import dh
        >>> parameters = load_pem_parameters(parameters_pem_data)
        >>> isinstance(parameters, dh.DHParameters)
        True

    :param bytes data: The PEM encoded parameters data.

    :param backend: An optional instance of
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

.. function:: load_der_private_key(data, password, backend=None)

    .. versionadded:: 0.8

    Deserialize a private key from DER encoded data to one of the supported
    asymmetric private key types.

    :param data: The DER encoded key data.
    :type data: :term:`bytes-like`

    :param password: The password to use to decrypt the data. Should
        be ``None`` if the private key is not encrypted.
    :type password: :term:`bytes-like`

    :param backend: An optional instance of
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

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized key
        is of a type that is not supported by the backend.

    .. doctest::

        >>> from cryptography.hazmat.primitives.asymmetric import rsa
        >>> from cryptography.hazmat.primitives.serialization import load_der_private_key
        >>> key = load_der_private_key(der_data, password=None)
        >>> isinstance(key, rsa.RSAPrivateKey)
        True

.. function:: load_der_public_key(data, backend=None)

    .. versionadded:: 0.8

    Deserialize a public key from DER encoded data to one of the supported
    asymmetric public key types. The DER encoded data is typically a
    ``subjectPublicKeyInfo`` payload as specified in :rfc:`5280`.

    :param bytes data: The DER encoded key data.

    :param backend: An optional instance of
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

        >>> from cryptography.hazmat.primitives.asymmetric import rsa
        >>> from cryptography.hazmat.primitives.serialization import load_der_public_key
        >>> key = load_der_public_key(public_der_data)
        >>> isinstance(key, rsa.RSAPublicKey)
        True

.. function:: load_der_parameters(data, backend=None)

    .. versionadded:: 2.0

    Deserialize parameters from DER encoded data to one of the supported
    asymmetric parameters types.

    :param bytes data: The DER encoded parameters data.

    :param backend: An optional instance of
        :class:`~cryptography.hazmat.backends.interfaces.DERSerializationBackend`.

    :returns: Currently only
        :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`
        supported.

    :raises ValueError: If the DER data's structure could not be decoded
        successfully.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized key is of a type that
        is not supported by the backend.

    .. doctest::

        >>> from cryptography.hazmat.primitives.asymmetric import dh
        >>> from cryptography.hazmat.primitives.serialization import load_der_parameters
        >>> parameters = load_der_parameters(parameters_der_data)
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

.. function:: load_ssh_public_key(data, backend=None)

    .. versionadded:: 0.7

    Deserialize a public key from OpenSSH (:rfc:`4253` and
    `PROTOCOL.certkeys`_) encoded data to an
    instance of the public key type for the specified backend.

    :param data: The OpenSSH encoded key data.
    :type data: :term:`bytes-like`

    :param backend: An optional backend which implements
        :class:`~cryptography.hazmat.backends.interfaces.RSABackend`,
        :class:`~cryptography.hazmat.backends.interfaces.DSABackend`, or
        :class:`~cryptography.hazmat.backends.interfaces.EllipticCurveBackend`
        depending on the key's type.

    :returns: One of
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
        , or
        :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`,
        depending on the contents of ``data``.

    :raises ValueError: If the OpenSSH data could not be properly decoded or
        if the key is not in the proper format.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized
        key is of a type that is not supported.

OpenSSH Private Key
~~~~~~~~~~~~~~~~~~~

The format used by OpenSSH to store private keys, as approximately specified
in `PROTOCOL.key`_.

An example ECDSA key in OpenSSH format::

    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
    1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRI0fWnI1CxX7qYqp0ih6bxjhGmUrZK
    /Axf8vhM8Db3oH7CFR+JdL715lUdu4XCWvQZKVf60/h3kBFhuxQC23XjAAAAqKPzVaOj81
    WjAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEjR9acjULFfupiq
    nSKHpvGOEaZStkr8DF/y+EzwNvegfsIVH4l0vvXmVR27hcJa9BkpV/rT+HeQEWG7FALbde
    MAAAAga/VGV2asRlL3kXXao0aochQ59nXHA2xEGeAoQd952r0AAAAJbWFya29AdmZmAQID
    BAUGBw==
    -----END OPENSSH PRIVATE KEY-----

.. function:: load_ssh_private_key(data, password, backend=None)

    .. versionadded:: 3.0

    Deserialize a private key from OpenSSH encoded data to an
    instance of the private key type for the specified backend.

    :param data: The PEM encoded OpenSSH private key data.
    :type data: :term:`bytes-like`

    :param bytes password: Password bytes to use to decrypt
        password-protected key. Or ``None`` if not needed.

    :param backend: An optional backend which implements
        :class:`~cryptography.hazmat.backends.interfaces.RSABackend`,
        :class:`~cryptography.hazmat.backends.interfaces.DSABackend`, or
        :class:`~cryptography.hazmat.backends.interfaces.EllipticCurveBackend`
        depending on the key's type.

    :returns: One of
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
        or
        :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`,
        depending on the contents of ``data``.

    :raises ValueError: If the OpenSSH data could not be properly decoded,
        if the key is not in the proper format or the incorrect password
        was provided.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized
        key is of a type that is not supported.

PKCS12
~~~~~~

.. currentmodule:: cryptography.hazmat.primitives.serialization.pkcs12

PKCS12 is a binary format described in :rfc:`7292`. It can contain
certificates, keys, and more. PKCS12 files commonly have a ``pfx`` or ``p12``
file suffix.

.. note::

    ``cryptography`` only supports a single private key and associated
    certificates when parsing PKCS12 files at this time.

.. function:: load_key_and_certificates(data, password, backend=None)

    .. versionadded:: 2.5

    Deserialize a PKCS12 blob.

    :param data: The binary data.
    :type data: :term:`bytes-like`

    :param password: The password to use to decrypt the data. ``None``
        if the PKCS12 is not encrypted.
    :type password: :term:`bytes-like`

    :param backend: An optional backend instance.

    :returns: A tuple of
        ``(private_key, certificate, additional_certificates)``.
        ``private_key`` is a private key type or ``None``, ``certificate``
        is either the :class:`~cryptography.x509.Certificate` whose public key
        matches the private key in the PKCS 12 object or ``None``, and
        ``additional_certificates`` is a list of all other
        :class:`~cryptography.x509.Certificate` instances in the PKCS12 object.

.. function:: serialize_key_and_certificates(name, key, cert, cas, encryption_algorithm)

    .. versionadded:: 3.0

    .. warning::

        PKCS12 encryption is not secure and should not be used as a security
        mechanism. Wrap a PKCS12 blob in a more secure envelope if you need
        to store or send it safely. Encryption is provided for compatibility
        reasons only.

    Serialize a PKCS12 blob.

    .. note::

        Due to `a bug in Firefox`_ it's not possible to load unencrypted PKCS12
        blobs in Firefox.

    :param name: The friendly name to use for the supplied certificate and key.
    :type name: bytes

    :param key: The private key to include in the structure.
    :type key: An
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`
        ,
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization`
        , or
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization`
        object.

    :param cert: The certificate associated with the private key.
    :type cert: :class:`~cryptography.x509.Certificate` or ``None``

    :param cas: An optional set of certificates to also include in the structure.
    :type cas: list of :class:`~cryptography.x509.Certificate` or ``None``

    :param encryption_algorithm: The encryption algorithm that should be used
        for the key and certificate. An instance of an object conforming to the
        :class:`~cryptography.hazmat.primitives.serialization.KeySerializationEncryption`
        interface. PKCS12 encryption is **very weak** and should not be used
        as a security boundary.

    :return bytes: Serialized PKCS12.

PKCS7
~~~~~

.. currentmodule:: cryptography.hazmat.primitives.serialization.pkcs7

PKCS7 is a format described in :rfc:`2315`, among other specifications. It can
contain certificates, CRLs, and much more. PKCS7 files commonly have a ``p7b``,
``p7m``, or ``p7s`` file suffix but other suffixes are also seen in the wild.

.. note::

    ``cryptography`` only supports parsing certificates from PKCS7 files at
    this time.

.. function:: load_pem_pkcs7_certificates(data)

    .. versionadded:: 3.1

    Deserialize a PEM encoded PKCS7 blob to a list of certificates. PKCS7 can
    contain many other types of data, including CRLs, but this function will
    ignore everything except certificates.

    :param data: The data.
    :type data: bytes

    :returns: A list of :class:`~cryptography.x509.Certificate`.

    :raises ValueError: If the PKCS7 data could not be loaded.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the PKCS7 data
        is of a type that is not supported.

.. function:: load_der_pkcs7_certificates(data)

    .. versionadded:: 3.1

    Deserialize a DER encoded PKCS7 blob to a list of certificates. PKCS7 can
    contain many other types of data, including CRLs, but this function will
    ignore everything except certificates.

    :param data: The data.
    :type data: bytes

    :returns: A list of :class:`~cryptography.x509.Certificate`.

    :raises ValueError: If the PKCS7 data could not be loaded.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the PKCS7 data
        is of a type that is not supported.

.. testsetup::

    ca_key = b"""
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgA8Zqz5vLeR0ePZUe
    jBfdyMmnnI4U5uAJApWTsMn/RuWhRANCAAQY/8+7+Tm49d3D7sBAiwZ1BqtPzdgs
    UiROH+AQRme1XxW5Yr07zwxvvhr3tKEPtLnLboazUPlsUb/Bgte+xfkF
    -----END PRIVATE KEY-----
    """.strip()

    ca_cert = b"""
    -----BEGIN CERTIFICATE-----
    MIIBUTCB96ADAgECAgIDCTAKBggqhkjOPQQDAjAnMQswCQYDVQQGEwJVUzEYMBYG
    A1UEAwwPY3J5cHRvZ3JhcGh5IENBMB4XDTE3MDEwMTEyMDEwMFoXDTM4MTIzMTA4
    MzAwMFowJzELMAkGA1UEBhMCVVMxGDAWBgNVBAMMD2NyeXB0b2dyYXBoeSBDQTBZ
    MBMGByqGSM49AgEGCCqGSM49AwEHA0IABBj/z7v5Obj13cPuwECLBnUGq0/N2CxS
    JE4f4BBGZ7VfFblivTvPDG++Gve0oQ+0uctuhrNQ+WxRv8GC177F+QWjEzARMA8G
    A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhANES742XWm64tkGnz8Dn
    pG6u2lHkZFQr3oaVvPcemvlbAiEA0WGGzmYx5C9UvfXIK7NEziT4pQtyESE0uRVK
    Xw4nMqk=
    -----END CERTIFICATE-----
    """.strip()


.. class:: PKCS7SignatureBuilder

    The PKCS7 signature builder can create both basic PKCS7 signed messages as
    well as S/MIME messages, which are commonly used in email. S/MIME has
    multiple versions, but this implements a subset of :rfc:`2632`, also known
    as S/MIME Version 3.

    .. versionadded:: 3.2

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import hashes, serialization
        >>> from cryptography.hazmat.primitives.serialization import pkcs7
        >>> cert = x509.load_pem_x509_certificate(ca_cert)
        >>> key = serialization.load_pem_private_key(ca_key, None)
        >>> options = [pkcs7.PKCS7Options.DetachedSignature]
        >>> pkcs7.PKCS7SignatureBuilder().set_data(
        ...     b"data to sign"
        ... ).add_signer(
        ...     cert, key, hashes.SHA256()
        ... ).sign(
        ...     serialization.Encoding.SMIME, options
        ... )
        b'...'

    .. method:: set_data(data)

        :param data: The data to be hashed and signed.
        :type data: :term:`bytes-like`

    .. method:: add_signer(certificate, private_key, hash_algorithm)

        :param certificate: The :class:`~cryptography.x509.Certificate`.

        :param private_key: The
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey` or
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
            associated with the certificate provided.

        :param hash_algorithm: The
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` that
            will be used to generate the signature. This must be an instance of
            :class:`~cryptography.hazmat.primitives.hashes.SHA1`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA224`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA256`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA384`, or
            :class:`~cryptography.hazmat.primitives.hashes.SHA512`.

    .. method:: add_certificate(certificate)

        Add an additional certificate (typically used to help build a
        verification chain) to the PKCS7 structure. This method may
        be called multiple times to add as many certificates as desired.

        :param certificate: The :class:`~cryptography.x509.Certificate` to add.

    .. method:: sign(encoding, options, backend=None)

        :param encoding: :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`,
            or :attr:`~cryptography.hazmat.primitives.serialization.Encoding.SMIME`.

        :param options: A list of
            :class:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7Options`.

        :return bytes: The signed PKCS7 message.

        :param backend: An optional backend.


.. class:: PKCS7Options

    .. versionadded:: 3.2

    An enumeration of options for PKCS7 signature creation.

    .. attribute:: Text

        The text option adds ``text/plain`` headers to an S/MIME message when
        serializing to
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.SMIME`.
        This option is disallowed with ``DER`` serialization.

    .. attribute:: Binary

        Signing normally converts line endings (LF to CRLF). When
        passing this option the data will not be converted.

    .. attribute:: DetachedSignature

        Don't embed the signed data within the ASN.1. When signing with
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.SMIME`
        this also results in the data being added as clear text before the
        PEM encoded structure.

    .. attribute:: NoCapabilities

        PKCS7 structures contain a ``MIMECapabilities`` section inside the
        ``authenticatedAttributes``. Passing this as an option removes
        ``MIMECapabilities``.

    .. attribute:: NoAttributes

        PKCS7 structures contain an ``authenticatedAttributes`` section.
        Passing this as an option removes that section. Note that if you
        pass ``NoAttributes`` you can't pass ``NoCapabilities`` since
        ``NoAttributes`` removes ``MIMECapabilities`` and more.

    .. attribute:: NoCerts

        Don't include the signer's certificate in the PKCS7 structure. This can
        reduce the size of the signature but requires that the recipient can
        obtain the signer's certificate by other means (for example from a
        previously signed message).

Serialization Formats
~~~~~~~~~~~~~~~~~~~~~

.. currentmodule:: cryptography.hazmat.primitives.serialization

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

        A PEM encoded RSA key will look like::

            -----BEGIN RSA PRIVATE KEY-----
            ...
            -----END RSA PRIVATE KEY-----

    .. attribute:: PKCS8

        A more modern format for serializing keys which allows for better
        encryption. Choose this unless you have explicit legacy compatibility
        requirements.

        A PEM encoded key will look like::

            -----BEGIN PRIVATE KEY-----
            ...
            -----END PRIVATE KEY-----

    .. attribute:: Raw

        .. versionadded:: 2.5

        A raw format used by :doc:`/hazmat/primitives/asymmetric/x448`. It is a
        binary format and is invalid for other key types.

    .. attribute:: OpenSSH

        .. versionadded:: 3.0

        Custom private key format for OpenSSH, internals are based on SSH protocol
        and not ASN1.  Requires
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`
        encoding.

        A PEM encoded OpenSSH key will look like::

            -----BEGIN OPENSSH PRIVATE KEY-----
            ...
            -----END OPENSSH PRIVATE KEY-----


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

        A PEM encoded key will look like::

            -----BEGIN PUBLIC KEY-----
            ...
            -----END PUBLIC KEY-----

    .. attribute:: PKCS1

        Just the public key elements (without the algorithm identifier). This
        format is RSA only, but is used by some older systems.

        A PEM encoded key will look like::

            -----BEGIN RSA PUBLIC KEY-----
            ...
            -----END RSA PUBLIC KEY-----

    .. attribute:: OpenSSH

        .. versionadded:: 1.4

        The public key format used by OpenSSH (e.g. as found in
        ``~/.ssh/id_rsa.pub`` or ``~/.ssh/authorized_keys``).

    .. attribute:: Raw

        .. versionadded:: 2.5

        A raw format used by :doc:`/hazmat/primitives/asymmetric/x448`. It is a
        binary format and is invalid for other key types.

    .. attribute:: CompressedPoint

        .. versionadded:: 2.5

        A compressed elliptic curve public key as defined in ANSI X9.62 section
        4.3.6 (as well as `SEC 1 v2.0`_).

    .. attribute:: UncompressedPoint

        .. versionadded:: 2.5

        An uncompressed elliptic curve public key as defined in ANSI X9.62
        section 4.3.6 (as well as `SEC 1 v2.0`_).

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
    , :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKeyWithSerialization`,
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization`,
    and
    :class:`~cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey`
    as well as ``public_bytes`` on
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`,
    and
    :class:`~cryptography.hazmat.primitives.asymmetric.x448.X448PublicKey`.

    .. attribute:: PEM

        .. versionadded:: 0.8

        For PEM format. This is a base64 format with delimiters.

    .. attribute:: DER

        .. versionadded:: 0.9

        For DER format. This is a binary format.

    .. attribute:: OpenSSH

        .. versionadded:: 1.4

        The format used by OpenSSH public keys. This is a text format.

    .. attribute:: Raw

        .. versionadded:: 2.5

        A raw format used by :doc:`/hazmat/primitives/asymmetric/x448`. It is a
        binary format and is invalid for other key types.

    .. attribute:: X962

        .. versionadded:: 2.5

        The format used by elliptic curve point encodings. This is a binary
        format.

    .. attribute:: SMIME

        .. versionadded:: 3.2

        An output format used for PKCS7. This is a text format.


Serialization Encryption Types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: KeySerializationEncryption

    Objects with this interface are usable as encryption types with methods
    like ``private_bytes`` available on
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
    ,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
    , :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`
    and
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.
    All other classes in this section represent the available choices for
    encryption and have this interface.

.. class:: BestAvailableEncryption(password)

    Encrypt using the best available encryption for a given key's backend.
    This is a curated encryption choice and the algorithm may change over
    time.

    :param bytes password: The password to use for encryption.

.. class:: NoEncryption

    Do not encrypt.


.. _`a bug in Firefox`: https://bugzilla.mozilla.org/show_bug.cgi?id=773111
.. _`PKCS3`: https://www.teletrust.de/fileadmin/files/oid/oid_pkcs-3v1-4.pdf
.. _`SEC 1 v2.0`: https://www.secg.org/sec1-v2.pdf
.. _`PROTOCOL.key`: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
.. _`PROTOCOL.certkeys`: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
