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
method on the key object. Documentation for these methods is found in the
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

.. function:: load_pem_private_key(data, password, *, unsafe_skip_rsa_key_validation=False)

    .. versionadded:: 0.6

    .. note::
        SSH private keys are a different format and must be loaded with
        :func:`load_ssh_private_key`.

    Deserialize a private key from PEM encoded data to one of the supported
    asymmetric private key types.

    :param data: The PEM encoded key data.
    :type data: :term:`bytes-like`

    :param password: The password to use to decrypt the data. Should
        be ``None`` if the private key is not encrypted.
    :type password: :term:`bytes-like`

    :param unsafe_skip_rsa_key_validation:

        .. versionadded:: 39.0.0

        A keyword-only argument that defaults to ``False``. If ``True``
        RSA private keys will not be validated. This significantly speeds up
        loading the keys, but is :term:`unsafe` unless you are certain the
        key is valid. User supplied keys should never be loaded with this
        parameter set to ``True``. If you do load an invalid key this way and
        attempt to use it OpenSSL may hang, crash, or otherwise misbehave.

    :type unsafe_skip_rsa_key_validation: bool

    :returns: One of
        :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey`,
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
        type is not supported by the OpenSSL version ``cryptography`` is using.

.. function:: load_pem_public_key(data)

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

    :returns: One of
        :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.x448.X448PublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`,
        or
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
        depending on the contents of ``data``.

    :raises ValueError: If the PEM data's structure could not be decoded
        successfully.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized key
        type is not supported by the OpenSSL version ``cryptography`` is using.

.. function:: load_pem_parameters(data)
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

    :returns: Currently only
        :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`
        supported.

    :raises ValueError: If the PEM data's structure could not be decoded
        successfully.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized key
        type is not supported by the OpenSSL version ``cryptography`` is using.

DER
~~~

DER is an ASN.1 encoding type. There are no encapsulation boundaries and the
data is binary. DER keys may be in a variety of formats, but as long as you
know whether it is a public or private key the loading functions will handle
the rest.

.. function:: load_der_private_key(data, password, *, unsafe_skip_rsa_key_validation=False)

    .. versionadded:: 0.8

    Deserialize a private key from DER encoded data to one of the supported
    asymmetric private key types.

    :param data: The DER encoded key data.
    :type data: :term:`bytes-like`

    :param password: The password to use to decrypt the data. Should
        be ``None`` if the private key is not encrypted.
    :type password: :term:`bytes-like`

    :param unsafe_skip_rsa_key_validation:

        .. versionadded:: 39.0.0

        A keyword-only argument that defaults to ``False``. If ``True``
        RSA private keys will not be validated. This significantly speeds up
        loading the keys, but is :term:`unsafe` unless you are certain the
        key is valid. User supplied keys should never be loaded with this
        parameter set to ``True``. If you do load an invalid key this way and
        attempt to use it OpenSSL may hang, crash, or otherwise misbehave.

    :type unsafe_skip_rsa_key_validation: bool

    :returns: One of
        :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey`,
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
        type is not supported by the OpenSSL version ``cryptography`` is using.

    .. doctest::

        >>> from cryptography.hazmat.primitives.asymmetric import rsa
        >>> from cryptography.hazmat.primitives.serialization import load_der_private_key
        >>> key = load_der_private_key(der_data, password=None)
        >>> isinstance(key, rsa.RSAPrivateKey)
        True

.. function:: load_der_public_key(data)

    .. versionadded:: 0.8

    Deserialize a public key from DER encoded data to one of the supported
    asymmetric public key types. The DER encoded data is typically a
    ``subjectPublicKeyInfo`` payload as specified in :rfc:`5280`.

    :param bytes data: The DER encoded key data.

    :returns: One of
        :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.x448.X448PublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
        :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`,
        or
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
        depending on the contents of ``data``.

    :raises ValueError: If the DER data's structure could not be decoded
        successfully.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized key
        type is not supported by the OpenSSL version ``cryptography`` is using.

    .. doctest::

        >>> from cryptography.hazmat.primitives.asymmetric import rsa
        >>> from cryptography.hazmat.primitives.serialization import load_der_public_key
        >>> key = load_der_public_key(public_der_data)
        >>> isinstance(key, rsa.RSAPublicKey)
        True

.. function:: load_der_parameters(data)

    .. versionadded:: 2.0

    Deserialize parameters from DER encoded data to one of the supported
    asymmetric parameters types.

    :param bytes data: The DER encoded parameters data.

    :returns: Currently only
        :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`
        supported.

    :raises ValueError: If the DER data's structure could not be decoded
        successfully.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized key
        type is not supported by the OpenSSL version ``cryptography`` is using.

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


.. data:: SSHPublicKeyTypes

    .. versionadded:: 40.0.0

    Type alias: A union of public key types accepted for SSH:
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
    , or
    :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`.


.. function:: load_ssh_public_key(data)

    .. versionadded:: 0.7

    .. note::

        SSH DSA key support is deprecated and will be removed in a future
        release.

    Deserialize a public key from OpenSSH (:rfc:`4253` and
    `PROTOCOL.certkeys`_) encoded data to an
    instance of the public key type.

    :param data: The OpenSSH encoded key data.
    :type data: :term:`bytes-like`

    :returns: One of :data:`SSHPublicKeyTypes` depending on the contents of
        ``data``.

    :raises ValueError: If the OpenSSH data could not be properly decoded or
        if the key is not in the proper format.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized
        key is of a type that is not supported.


.. function:: ssh_key_fingerprint(key, hash_algorithm)

    .. versionadded:: 45.0.0

    Computes the fingerprint of an SSH public key. The fingerprint is the raw
    bytes of the hash, depending on your use you may need to encode the data as
    base64 or hex.

    :param key: The public key to compute the fingerprint for.
    :type key: One of :data:`SSHPublicKeyTypes`

    :param hash_algorithm: The hash algorithm to use, either ``MD5()`` or
        ``SHA256()``.

    :return: The key fingerprint.
    :rtype: bytes

    .. code-block:: pycon

        >>> from cryptography.hazmat.primitives.serialization import load_ssh_public_key, ssh_key_fingerprint
        >>> key_data = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhVNvf1vigXfagQXKjdKN5zEF12KWVMVdDrU3sVLhgd user@example.com"
        >>> public_key = load_ssh_public_key(key_data)
        >>> md5_fingerprint = ssh_key_fingerprint(public_key, hashes.MD5())
        >>> md5_fingerprint
        b'\x95\xf6\xc0\xe3so\xaen\xcc\x98\xbb\xf4\xd8BJ\x15'
        >>> sha256_fingerprint = ssh_key_fingerprint(public_key, hashes.SHA256())
        >>> sha256_fingerprint
        b'R\x0f*!\x99f9\x9a\xcd\x98[\xe8-&\xbah\xa6x\x96\x87\xb3\xf9\xe0\x9b\xb1,\xcc\xbdt\xd4\xc3\xb7'


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

.. data:: SSHPrivateKeyTypes

    .. versionadded:: 40.0.0

    Type alias: A union of private key types accepted for SSH:
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
    or
    :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`.


.. function:: load_ssh_private_key(data, password, *, unsafe_skip_rsa_key_validation=False)

    .. versionadded:: 3.0

    .. note::

        SSH DSA key support is deprecated and will be removed in a future
        release.

    Deserialize a private key from OpenSSH encoded data to an
    instance of the private key type.

    :param data: The PEM encoded OpenSSH private key data.
    :type data: :term:`bytes-like`

    :param bytes password: Password bytes to use to decrypt
        password-protected key. Or ``None`` if not needed.

    :param unsafe_skip_rsa_key_validation:

        .. versionadded:: 45.0.0

        A keyword-only argument that defaults to ``False``. If ``True``
        RSA private keys will not be validated. This significantly speeds up
        loading the keys, but is :term:`unsafe` unless you are certain the
        key is valid. User supplied keys should never be loaded with this
        parameter set to ``True``. If you do load an invalid key this way and
        attempt to use it OpenSSL may hang, crash, or otherwise misbehave.

    :type unsafe_skip_rsa_key_validation: bool

    :returns: One of :data:`SSHPrivateKeyTypes` depending on the contents of
        ``data``.

    :raises ValueError: If the OpenSSH data could not be properly decoded,
        if the key is not in the proper format or the incorrect password
        was provided.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized
        key is of a type that is not supported.


OpenSSH Certificate
~~~~~~~~~~~~~~~~~~~

The format used by OpenSSH for certificates, as specified in
`PROTOCOL.certkeys`_.

.. data:: SSHCertPublicKeyTypes

    .. versionadded:: 40.0.0

    Type alias: A union of public key types supported for SSH
    certificates:
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
    or
    :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`

.. data:: SSHCertPrivateKeyTypes

    .. versionadded:: 40.0.0

    Type alias: A union of private key types supported for SSH
    certificates:
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
    or
    :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`

.. function:: load_ssh_public_identity(data)

    .. versionadded:: 40.0.0

    .. note::

        This function does not support parsing certificates with DSA public
        keys or signatures from DSA certificate authorities. DSA is a
        deprecated algorithm and should not be used.

    Deserialize an OpenSSH encoded identity to an instance of
    :class:`SSHCertificate` or the appropriate public key type.
    Parsing a certificate does not verify anything. It is up to the caller to
    perform any necessary verification.

    :param data: The OpenSSH encoded data.
    :type data: bytes

    :returns: :class:`SSHCertificate` or one of :data:`SSHCertPublicKeyTypes`.

    :raises ValueError: If the OpenSSH data could not be properly decoded.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the data contains
        a public key type that is not supported.


.. class:: SSHCertificate

    .. versionadded:: 40.0.0

    .. attribute:: nonce

        :type: bytes

        The nonce field is a CA-provided random value of arbitrary length
        (but typically 16 or 32 bytes) included to make attacks that depend on
        inducing collisions in the signature hash infeasible.

    .. method:: public_key()

        The public key contained in the certificate, one of
        :data:`SSHCertPublicKeyTypes`.

    .. attribute:: serial

        :type: int

        Serial is an optional certificate serial number set by the CA to
        provide an abbreviated way to refer to certificates from that CA.
        If a CA does not wish to number its certificates, it must set this
        field to zero.

    .. attribute:: type

        :type: :class:`SSHCertificateType`

        Type specifies whether this certificate is for identification of a user
        or a host.

    .. attribute:: key_id

        :type: bytes

        This is a free-form text field that is filled in by the CA at the time
        of signing; the intention is that the contents of this field are used to
        identify the identity principal in log messages.

    .. attribute:: valid_principals

        :type: list[bytes]

        "valid principals" is a list containing one or more principals as
        byte strings. These principals list the names for which this
        certificate is valid; hostnames for host certificates and
        usernames for user certificates. As a special case, an
        empty list means the certificate is valid for any principal of
        the specified type.

    .. attribute:: valid_after

        :type: int

        An integer representing the Unix timestamp (in UTC) after which the
        certificate is valid. **This time is inclusive.**

    .. attribute:: valid_before

        :type: int

        An integer representing the Unix timestamp (in UTC) before which the
        certificate is valid. **This time is not inclusive.**

    .. attribute:: critical_options

        :type: dict[bytes, bytes]

        Critical options is a dict of zero or more options that are
        critical for the certificate to be considered valid. If
        any of these options are not supported by the implementation, the
        certificate must be rejected.

    .. attribute:: extensions

        :type: dict[bytes, bytes]

        Extensions is a dict of zero or more options that are
        non-critical for the certificate to be considered valid. If any of
        these options are not supported by the implementation, the
        implementation may safely ignore them.

    .. method:: signature_key()

        The public key used to sign the certificate, one of
        :data:`SSHCertPublicKeyTypes`.

    .. method:: verify_cert_signature()

        .. warning::

            This method does not validate anything about whether the
            signing key is trusted! Callers are responsible for validating
            trust in the signer.

        Validates that the signature on the certificate was created by
        the private key associated with the certificate's signature key
        and that the certificate has not been changed since signing.

        :return: None
        :raises: :class:`~cryptography.exceptions.InvalidSignature` if the
            signature is invalid.

    .. method:: public_bytes()

        :return: The serialized certificate in OpenSSH format.
        :rtype: bytes


.. class:: SSHCertificateType

    .. versionadded:: 40.0.0

    An enumeration of the types of SSH certificates.

    .. attribute:: USER

        The cert is intended for identification of a user. Corresponds to the
        value ``1``.

    .. attribute:: HOST

        The cert is intended for identification of a host. Corresponds to the
        value ``2``.

SSH Certificate Builder
~~~~~~~~~~~~~~~~~~~~~~~

.. class:: SSHCertificateBuilder

    .. versionadded:: 40.0.0

    .. note::

        This builder does not support generating certificates with DSA public
        keys or creating signatures with DSA certificate authorities. DSA is a
        deprecated algorithm and should not be used.

    .. doctest::

        >>> import datetime
        >>> from cryptography.hazmat.primitives.asymmetric import ec
        >>> from cryptography.hazmat.primitives.serialization import (
        ...     SSHCertificateType, SSHCertificateBuilder
        ... )
        >>> signing_key = ec.generate_private_key(ec.SECP256R1())
        >>> public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
        >>> valid_after = datetime.datetime(
        ...     2023, 1, 1, 1, tzinfo=datetime.timezone.utc
        ... ).timestamp()
        >>> valid_before = datetime.datetime(
        ...     2023, 7, 1, 1, tzinfo=datetime.timezone.utc
        ... ).timestamp()
        >>> key_id = b"a_key_id"
        >>> valid_principals = [b"eve", b"alice"]
        >>> builder = (
        ...     SSHCertificateBuilder()
        ...     .public_key(public_key)
        ...     .type(SSHCertificateType.USER)
        ...     .valid_before(valid_before)
        ...     .valid_after(valid_after)
        ...     .key_id(b"a_key_id")
        ...     .valid_principals(valid_principals)
        ...     .add_extension(b"no-touch-required", b"")
        ... )
        >>> builder.sign(signing_key).public_bytes()
        b'...'

    .. method:: public_key(public_key)

        :param public_key: The public key to be included in the certificate.
            This value is required.
        :type public_key: :data:`SSHCertPublicKeyTypes`

    .. method:: serial(serial)

        :param int serial: The serial number to be included in the certificate.
            This is not a required value and will be set to zero if not
            provided. Value must be between 0 and 2:sup:`64` - 1, inclusive.

    .. method:: type(type)

        :param type: The type of the certificate. There are two options,
            user or host.
        :type type: :class:`SSHCertificateType`

    .. method:: key_id(key_id)

        :param key_id: The key ID to be included in the certificate. This is
            not a required value.
        :type key_id: bytes

    .. method:: valid_principals(valid_principals)

        :param valid_principals: A list of principals that the certificate is
            valid for. This is a required value unless
            :meth:`valid_for_all_principals` has been called.
        :type valid_principals: list[bytes]

    .. method:: valid_for_all_principals()

        Marks the certificate as valid for all principals. This cannot be
        set if principals have been added via :meth:`valid_principals`.

    .. method:: valid_after(valid_after)

        :param int valid_after: The Unix timestamp (in UTC) that marks the
            activation time for the certificate. This is a required value.

    .. method:: valid_before(valid_before)

        :param int valid_before: The Unix timestamp (in UTC) that marks the
            expiration time for the certificate. This is a required value.

    .. method:: add_critical_option(name, value)

        :param name: The name of the critical option to add. No duplicates
            are allowed.
        :type name: bytes
        :param value: The value of the critical option to add. This is
            commonly an empty byte string.
        :type value: bytes

    .. method:: add_extension(name, value)

        :param name: The name of the extension to add. No duplicates are
            allowed.
        :type name: bytes
        :param value: The value of the extension to add.
        :type value: bytes

    .. method:: sign(private_key)

        :param private_key: The private key that will be used to sign the
            certificate.
        :type private_key: :data:`SSHCertPrivateKeyTypes`

        :return: The signed certificate.
        :rtype: :class:`SSHCertificate`

PKCS12
~~~~~~

.. currentmodule:: cryptography.hazmat.primitives.serialization.pkcs12

PKCS12 is a binary format described in :rfc:`7292`. It can contain
certificates, keys, and more. PKCS12 files commonly have a ``pfx`` or ``p12``
file suffix.

.. note::

    ``cryptography`` only supports a single private key and associated
    certificates when parsing PKCS12 files at this time.


.. data:: PKCS12PrivateKeyTypes

    .. versionadded:: 40.0.0

    Type alias: A union of private key types supported for PKCS12
    serialization:
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
    ,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
    ,
    :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`
    ,
    :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey`
    or
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.

.. function:: load_key_and_certificates(data, password)

    .. versionadded:: 2.5

    Deserialize a PKCS12 blob.

    :param data: The binary data.
    :type data: :term:`bytes-like`

    :param password: The password to use to decrypt the data. ``None``
        if the PKCS12 is not encrypted.
    :type password: :term:`bytes-like`

    :returns: A tuple of
        ``(private_key, certificate, additional_certificates)``.
        ``private_key`` is a private key type or ``None``, ``certificate``
        is either the :class:`~cryptography.x509.Certificate` whose public key
        matches the private key in the PKCS 12 object or ``None``, and
        ``additional_certificates`` is a list of all other
        :class:`~cryptography.x509.Certificate` instances in the PKCS12 object.

.. function:: load_pkcs12(data, password)

    .. versionadded:: 36.0.0

    Deserialize a PKCS12 blob, and return a
    :class:`~cryptography.hazmat.primitives.serialization.pkcs12.PKCS12KeyAndCertificates`
    instance.

    :param data: The binary data.
    :type data: :term:`bytes-like`

    :param password: The password to use to decrypt the data. ``None``
        if the PKCS12 is not encrypted.
    :type password: :term:`bytes-like`

    :returns: A
        :class:`~cryptography.hazmat.primitives.serialization.pkcs12.PKCS12KeyAndCertificates`
        instance.

.. function:: serialize_key_and_certificates(name, key, cert, cas, encryption_algorithm)

    .. versionadded:: 3.0

    .. note::
        With OpenSSL 3.0.0+ the defaults for encryption when serializing PKCS12
        have changed and some versions of Windows and macOS will not be able to
        read the new format. Maximum compatibility can be achieved by using
        ``SHA1`` for MAC algorithm and
        :attr:`~cryptography.hazmat.primitives.serialization.pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC`
        for encryption algorithm as seen in the example below. However, users
        should avoid this unless required for compatibility.

    .. warning::

        PKCS12 encryption is typically not secure and should not be used as a
        security mechanism. Wrap a PKCS12 blob in a more secure envelope if you
        need to store or send it safely.

    Serialize a PKCS12 blob.

    .. note::

        Due to `a bug in Firefox`_ it's not possible to load unencrypted PKCS12
        blobs in Firefox.

    :param name: The friendly name to use for the supplied certificate and key.
    :type name: bytes

    :param key: The private key to include in the structure.
    :type key: :data:`PKCS12PrivateKeyTypes`

    :param cert: The certificate associated with the private key.
    :type cert: :class:`~cryptography.x509.Certificate` or ``None``

    :param cas: An optional set of certificates to also include in the structure.
        If a :class:`~cryptography.hazmat.primitives.serialization.pkcs12.PKCS12Certificate`
        is given, its friendly name will be serialized.
    :type cas: ``None``, or list of
        :class:`~cryptography.x509.Certificate`
        or
        :class:`~cryptography.hazmat.primitives.serialization.pkcs12.PKCS12Certificate`

    :param encryption_algorithm: The encryption algorithm that should be used
        for the key and certificate. An instance of an object conforming to the
        :class:`~cryptography.hazmat.primitives.serialization.KeySerializationEncryption`
        interface. PKCS12 encryption is typically **very weak** and should not
        be used as a security boundary.

    :return bytes: Serialized PKCS12.

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, load_pem_private_key, pkcs12
        >>> cert = x509.load_pem_x509_certificate(ca_cert)
        >>> key = load_pem_private_key(ca_key, None)
        >>> p12 = pkcs12.serialize_key_and_certificates(
        ...     b"friendlyname", key, cert, None, BestAvailableEncryption(b"password")
        ... )

    This example uses an ``encryption_builder()`` to create a PKCS12 with more
    compatible, but substantially less secure, encryption.

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.serialization import PrivateFormat, load_pem_private_key, pkcs12
        >>> encryption = (
        ...     PrivateFormat.PKCS12.encryption_builder().
        ...     kdf_rounds(50000).
        ...     key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).
        ...     hmac_hash(hashes.SHA1()).build(b"my password")
        ... )
        >>> cert = x509.load_pem_x509_certificate(ca_cert)
        >>> key = load_pem_private_key(ca_key, None)
        >>> p12 = pkcs12.serialize_key_and_certificates(
        ...     b"friendlyname", key, cert, None, encryption
        ... )

.. function:: serialize_java_truststore(pkcs12_certs, encryption_algorithm)

    .. versionadded:: 45.0.0

    .. warning::

        PKCS12 encryption is typically not secure and should not be used as a
        security mechanism. Wrap a PKCS12 blob in a more secure envelope if you
        need to store or send it safely.

    Serialize a PKCS12 blob containing provided certificates. Java expects an
    internal flag to denote truststore usage, which this function adds.

    :param certs: A set of certificates to also include in the structure.
    :type certs:

        A list of :class:`~cryptography.hazmat.primitives.serialization.pkcs12.PKCS12Certificate`
        instances.

    :param encryption_algorithm: The encryption algorithm that should be used
        for the key and certificate. An instance of an object conforming to the
        :class:`~cryptography.hazmat.primitives.serialization.KeySerializationEncryption`
        interface. PKCS12 encryption is typically **very weak** and should not
        be used as a security boundary.

    :return bytes: Serialized PKCS12.

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
        >>> cert = x509.load_pem_x509_certificate(ca_cert)
        >>> p12 = pkcs12.serialize_java_truststore(
        ...     [pkcs12.PKCS12Certificate(cert, b"friendlyname")], BestAvailableEncryption(b"password")
        ... )

.. class:: PKCS12Certificate(cert, friendly_name=None)

    .. versionadded:: 36.0.0

    Represents additional data provided for a certificate in a PKCS12 file.

    :param cert: The certificate to associate with the additional data.
    :type cert: :class:`~cryptography.x509.Certificate`

    :param friendly_name: An optional friendly name for the certificate.
    :type friendly_name: bytes or None

    .. attribute:: certificate

        A :class:`~cryptography.x509.Certificate` instance.

    .. attribute:: friendly_name

        :type: bytes or None

        An optional byte string containing the friendly name of the certificate.

.. class:: PKCS12KeyAndCertificates

    .. versionadded:: 36.0.0

    A simplified representation of a PKCS12 file.

    .. attribute:: key

        An optional private key belonging to
        :attr:`~cryptography.hazmat.primitives.serialization.pkcs12.PKCS12KeyAndCertificates.cert`
        (see :data:`PKCS12PrivateKeyTypes`).

    .. attribute:: cert

        An optional
        :class:`~cryptography.hazmat.primitives.serialization.pkcs12.PKCS12Certificate`
        instance belonging to the private key
        :attr:`~cryptography.hazmat.primitives.serialization.pkcs12.PKCS12KeyAndCertificates.key`.

    .. attribute:: additional_certs

        A list of :class:`~cryptography.hazmat.primitives.serialization.pkcs12.PKCS12Certificate`
        instances.

.. class:: PBES
    :canonical: cryptography.hazmat.primitives._serialization.PBES

    .. versionadded:: 38.0.0

    An enumeration of password-based encryption schemes used in PKCS12. These
    values are used with
    :class:`~cryptography.hazmat.primitives.serialization.KeySerializationEncryptionBuilder`.

    .. attribute:: PBESv1SHA1And3KeyTripleDESCBC

        PBESv1 using SHA1 as the KDF PRF and 3-key triple DES-CBC as the cipher.

    .. attribute:: PBESv2SHA256AndAES256CBC

        PBESv2 using SHA256 as the KDF PRF and AES256-CBC as the cipher. This
        is only supported on OpenSSL 3.0.0 or newer.


PKCS7
~~~~~

.. currentmodule:: cryptography.hazmat.primitives.serialization.pkcs7

PKCS7 is a format described in :rfc:`2315`, among other specifications. It can
contain certificates, CRLs, and much more. PKCS7 files commonly have a ``p7b``,
``p7m``, or ``p7s`` file suffix but other suffixes are also seen in the wild.

.. data:: PKCS7HashTypes

    .. versionadded:: 40.0.0

    Type alias: A union of hash types supported for PKCS7 serialization:
    :class:`~cryptography.hazmat.primitives.hashes.SHA1`,
    :class:`~cryptography.hazmat.primitives.hashes.SHA224`,
    :class:`~cryptography.hazmat.primitives.hashes.SHA256`,
    :class:`~cryptography.hazmat.primitives.hashes.SHA384`, or
    :class:`~cryptography.hazmat.primitives.hashes.SHA512`.

.. data:: PKCS7PrivateKeyTypes

    .. versionadded:: 40.0.0

    Type alias: A union of private key types supported for PKCS7 serialization:
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey` or
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`

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

.. function:: serialize_certificates(certs, encoding)

    .. versionadded:: 37.0.0

    Serialize a list of certificates to a PKCS7 structure.

    :param certs: A list of :class:`~cryptography.x509.Certificate`.
    :param encoding: :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`
        or :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`.
    :returns bytes: The serialized PKCS7 data.

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

    ca_cert_rsa = b"""
    -----BEGIN CERTIFICATE-----
    MIIExzCCAq+gAwIBAgIJAOcS06ClbtbJMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNV
    BAMMD2NyeXB0b2dyYXBoeSBDQTAeFw0yMDA5MTQyMTQwNDJaFw00ODAxMzEyMTQw
    NDJaMBoxGDAWBgNVBAMMD2NyeXB0b2dyYXBoeSBDQTCCAiIwDQYJKoZIhvcNAQEB
    BQADggIPADCCAgoCggIBANBIheRc1HT4MzV5GvUbDk9CFU6DTomRApNqRmizriRq
    m6OY4Ht3d71BXog6/IBkqAnZ4/XJQ40G4sVDb52k11oPvfJ/F5pc+6UqPBL+QGzY
    GkJoubAqXFpI6ow0qayFNQLv0T9o4yh0QQOoGvgCmv91qmitLrZNXu4U9S76G+Di
    GST+QyMkMxj+VsGRsRRBufV1urcnvFWjU6Q2+cr2cp0mMAG96NTyIskYiJ8vL03W
    z4DX4klO4X47fPmDnU/OMn4SbvMZ896j1L0J04S+uVThTkxQWcFcqXhX5qM8kzcj
    JUmybFlbf150j3WiucW48K/j7fJ0x9q3iUo4Gva0coScglJWcgo/BBCwFDw8NVba
    7npxSRMiaS3qTv0dEFcRnvByc+7hyGxxlWdTE9tHisUI1eZVk9P9ziqNOZKscY8Z
    X1+/C4M9X69Y7A8I74F5dO27IRycEgOrSo2z1NhfSwbqJr9a2TBtRsFinn8rjKBI
    zNn0E5p9jO1WjxtkcjHfXXpLN8FFMvoYI9l/K+ZWDm9sboaF8jrgozSc004AFemA
    H79mmCGVRKXn1vDAo4DLC6p3NiBFYQcYbW9V+beGD6srsF6xJtuY/UwtPROLWSzu
    CCrZ/4BlmpNsR0ehIFFvzEKjX6rR2yp3YKlguDbMBMKMpfSGxAFwcZ7OiaxR20UH
    AgMBAAGjEDAOMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBADSveDS4
    y2V/N6Li2n9ChGNdCMr/45M0cl+GpL55aA36AWYMRLv0wip7MWV3yOj4mkjGBlTE
    awKHH1FtetsE6B4a7M2hHhOXyXE60uUdptEx6ckGrJ1iyqu5cQUX1P+VnXbmOxfF
    bl+Ugzjbgirx239rA4ezkDRuOvKcCbDOFV/gw3ZHfJ/IQeRXIQRl/y51wcnFUvFM
    JEESYiijeDbEcY8r1/phmVQL0CO7WLMmTxlFj4X/TR3MTZWJQIap9GiLs5+n3QiO
    jsZ3GuFOomB8oTebYkXniwbNu5hgLP/seRQzGA7B9VDZryAhCtvGgjtQh0eW2Qxt
    sgmDJGOPKnKT3O5U0v3+IPLEYpe8JSzgAhhh6H1rAJRUNwP2gRcO4eOUJSkdl218
    fRNT0ILzosuWxwprER9ciMQF8q0JJKMhcfHRMH0S5mWVJAIkj68KY05oCy2zNyYa
    oruopKSWXe0Bzr40znm40P7xIkui2BGQMlDPpbCaEfLsLqyctfbdmMlxac/QgIfY
    TltrbqmI3MNy5uqGViGFpWPCB+kD8EsJF9nlKJXlu/i55qgUr/2/2CdeWlZDBP8A
    1fdzmpYpWnwhE0KobzLS2z3AwDxiY/RSWUfypLZA0K/lpaEtYB6UHMDZ0/8WqgZV
    gNucCuty0cA4Kf7eX1TlAKVwH8hTkVmJc2rX
    -----END CERTIFICATE-----
    """.strip()

    ca_key_rsa = b"""
    -----BEGIN PRIVATE KEY-----
    MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQDQSIXkXNR0+DM1
    eRr1Gw5PQhVOg06JkQKTakZos64kapujmOB7d3e9QV6IOvyAZKgJ2eP1yUONBuLF
    Q2+dpNdaD73yfxeaXPulKjwS/kBs2BpCaLmwKlxaSOqMNKmshTUC79E/aOModEED
    qBr4Apr/daporS62TV7uFPUu+hvg4hkk/kMjJDMY/lbBkbEUQbn1dbq3J7xVo1Ok
    NvnK9nKdJjABvejU8iLJGIifLy9N1s+A1+JJTuF+O3z5g51PzjJ+Em7zGfPeo9S9
    CdOEvrlU4U5MUFnBXKl4V+ajPJM3IyVJsmxZW39edI91ornFuPCv4+3ydMfat4lK
    OBr2tHKEnIJSVnIKPwQQsBQ8PDVW2u56cUkTImkt6k79HRBXEZ7wcnPu4chscZVn
    UxPbR4rFCNXmVZPT/c4qjTmSrHGPGV9fvwuDPV+vWOwPCO+BeXTtuyEcnBIDq0qN
    s9TYX0sG6ia/WtkwbUbBYp5/K4ygSMzZ9BOafYztVo8bZHIx3116SzfBRTL6GCPZ
    fyvmVg5vbG6GhfI64KM0nNNOABXpgB+/ZpghlUSl59bwwKOAywuqdzYgRWEHGG1v
    Vfm3hg+rK7BesSbbmP1MLT0Ti1ks7ggq2f+AZZqTbEdHoSBRb8xCo1+q0dsqd2Cp
    YLg2zATCjKX0hsQBcHGezomsUdtFBwIDAQABAoICAQDH6YQRvwPwzTWhkn7MWU6v
    xjbbJ+7e3T9CrNOttSBlNanzKU31U6KrFS4dxbgLqBEde3Rwud/LYZuRSPu9rLVC
    bS+crF3EPJEQY2xLspu1nOn/abMoolAIHEp7jiR5QVWzXulRWmQFtSed0eEowJ9y
    qMaKOAdI1RRToev/TfIqM/l8Z0ubVChzSdONcUAsuDU7ouc22r3K2Lv0Nwwkwc0a
    hse3NEdg9JNsvs6LM2fM52w9N3ircjm+xmxatPft3HTcSucREIzg2hDb7K2HkOQj
    0ykq2Eh97ml+56eocADBAEvO46FZVxf2WhxEBY8Xdz4VJMmDWJFmnZj5ksZWmrX6
    U5BfFY7DZvE2EpoZ5ph1Fm6dcXrJFkaZEyJLlzFKehXMipVenjCanIPpEEUvIz+p
    m0QVoNJRj/GcNyIEZ0BCXedBOUWU4XE1pG4r6oZqwUvcjsVrqXP5kbJMVybiS6Kd
    6T8ve+4qsn3ZvGRVKjInqf2WI0Wvum2sTF+4OAkYvFel9dKNjpYnnj4tLFc/EKWz
    9+pE/Zz5fMOyMD9qXM6bdVkPjWjy1vXmNW4qFCZljrb395hTvsAPMsO6bbAM+lu6
    YcdOAf8k7awTb79kPMrPcbCygyKSGN9C9T3a/Nhrbr3TPi9SD9hC5Q8bL9uSHcR2
    hgRQcApxsfDRrGwy2lheEQKCAQEA/Hrynao+k6sYtlDc/ueCjb323EzsuhOxPqUZ
    fKtGeFkJzKuaKTtymasvVpAAqJBEhTALrptGWlJQ0Y/EVaPpZ9pmk791EWNXdXsX
    wwufbHxm6K9aOeogev8cd+B/9wUAQPQVotyRzCcOfbVe7t81cBNktqam5Zb9Y4Zr
    qu63gBB1UttdmIF5qitl3JcFztlBjiza2UrqgVdKE+d9vLR84IBRy3dyQIOi6C1c
    y37GNgObjx8ZcUVV54/KgvoVvDkvN6TEbUdC9eQz7FW7DA7MMVqyDvWZrSjBzVhK
    2bTrd+Pi6S4n/ETvA6XRufHC8af4bdE2hzuq5VZO1kkgH37djwKCAQEA0y/YU0b4
    vCYpZ1MNhBFI6J9346DHD55Zu5dWFRqNkC0PiO6xEMUaUMbG4gxkiQPNT5WvddQs
    EbRQTnd4FFdqB7XWoH+wERN7zjbT+BZVrHVC4gxEEy33s5oXGn7/ATxaowo7I4oq
    15MwgZu3hBNxVUtuePZ6D9/ePNGOGOUtdMRrusmVX7gZEXxwvlLJXyVepl2V4JV1
    otI8EZCcoRhSfeYNEs4VhN0WmfMSV7ge0eFfVb6Lb+6PCcasYED8S0tBN2vjzvol
    zCMv8skPATm7SopqBDoBPcXCHwN/gUFXHf/lrvE6bbeX1ZMxnRYKdQLLNYyQK9cr
    nCUJXuNM21tVCQKCAQBapCkFwWDF0t8EVPOB78tG57QAUv2JsBgpzUvhHfwmqJCE
    Efc+ZkE2Oea8xOX3nhN7XUxUWxpewr6Q/XQW6smYpye8UzfMDkYPvylAtKN/Zwnq
    70kNEainf37Q6qAGJp14tCgwV89f44WoS7zRNQESQ2QczqeMNTCy0kdFDn6CU2ZL
    YMWxQopTNVFUaEOFhympySCoceTOmm/VxX22iXVrg6XZzgAOeTO69s4hoFm4eoMW
    Vqvjpmi4wT6K1w2GjWEOMPDz6ml3rX2WkxCbu5RDA7R4+mM5bzBkcBYvImyGliGY
    ZSGlx3mnbZhlkQ3Tg+IESt+wnRM1Uk7rT0VhCUKxAoIBABWYuPibM2iaRnWoiqNM
    2TXgyPPgRzsTqH2ElmsGEiACW6pXLohWf8Bu83u+ZLGWT/Kpjg3wqqkM1YGQuhjq
    b49mSxKSvECiy3BlLvwZ3J0MSNCxDG0hsEkPovk0r4NC1soBi9awlH0DMlyuve+l
    xVtBoYSBQC5LaICztWJaXXGpfJLXdo0ZWIbvQOBVuv4d5jYBMAiNgEAsW7Q4I6xd
    vmHdmsyngo/ZxCvuLZwG2jAAai1slPnXXY1UYeBeBO72PS8bu2o5LpBXsNmVMhGg
    A8U1rm3MOMBGbvmY8/sV4YDR4H0pch4yPja7HMHBtUQOCxXoz/2LvYv0RacMe5mb
    F3ECggEAWxQZnT8pObxKrISZpHSKi54VxuLYbemS63Tdr4HE/KuiFAvbM6AeZOki
    jbiMnqrCTOhJRS/i9HV78zSxRZZyVm961tnsjqMyaamX/S4yD7v3Vzu1mfsdVCa2
    Sl+JUUxsEgs/G3Fu6I/0TsCSn/HgNLM8b3f8TDkbpnOqKX165ddojXqSCfxjuYau
    Szih/+jF1dz2/zBye1ARkLRdY/SzlzGl0cVn8bfkE0YEde7wvQ624Biy7r9i1o40
    7cy/8EQBR2FcXpOAZ7UgOqgGLNhXnd4FPsX4ldKOf5De8FErQOFirJ8pCUxFGr0U
    fDWXtBuybAb5u+ZaVwHgqaaPCkKkVQ==
    -----END PRIVATE KEY-----
    """.strip()

    verify_cert = b"""
    -----BEGIN CERTIFICATE-----
    MIIBhjCCASygAwIBAgICAwkwCgYIKoZIzj0EAwIwJzELMAkGA1UEBhMCVVMxGDAW
    BgNVBAMMD2NyeXB0b2dyYXBoeSBDQTAgFw0xNzAxMDEwMTAwMDBaGA8yMTAwMDEw
    MTAwMDAwMFowJzELMAkGA1UEBhMCVVMxGDAWBgNVBAMMD2NyeXB0b2dyYXBoeSBD
    QTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBj/z7v5Obj13cPuwECLBnUGq0/N
    2CxSJE4f4BBGZ7VfFblivTvPDG++Gve0oQ+0uctuhrNQ+WxRv8GC177F+QWjRjBE
    MCEGA1UdEQEB/wQXMBWBE2V4YW1wbGVAZXhhbXBsZS5jb20wHwYDVR0jBBgwFoAU
    /Ou02BLyyT2Zwzxn9H03feYT7fowCgYIKoZIzj0EAwIDSAAwRQIgUwIdC0Emkd6f
    17DeOXTlmTAhwSDJ2FTuyHESwei7wJcCIQCnr9NpBxbtJfEzxHGGyd7PxgpOLi5u
    rk+8QfzGMmg/fw==
    -----END CERTIFICATE-----
    """.strip()

    verify_key = b"""
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgA8Zqz5vLeR0ePZUe
    jBfdyMmnnI4U5uAJApWTsMn/RuWhRANCAAQY/8+7+Tm49d3D7sBAiwZ1BqtPzdgs
    UiROH+AQRme1XxW5Yr07zwxvvhr3tKEPtLnLboazUPlsUb/Bgte+xfkF
    -----END PRIVATE KEY-----
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

    .. method:: add_signer(certificate, private_key, hash_algorithm, *, rsa_padding=None)

        :param certificate: The :class:`~cryptography.x509.Certificate`.

        :param private_key: The
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey` or
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
            associated with the certificate provided
            (matches :data:`PKCS7PrivateKeyTypes`).

        :param hash_algorithm: The
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` that
            will be used to generate the signature. This must be one of the
            types in :data:`PKCS7HashTypes`.

        :param rsa_padding:

            .. versionadded:: 42.0.0

            This is a keyword-only argument. If ``private_key`` is an
            ``RSAPrivateKey`` then this can be set to either
            :class:`~cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15` or
            :class:`~cryptography.hazmat.primitives.asymmetric.padding.PSS` to sign
            with those respective paddings. If this is ``None`` then RSA
            keys will default to ``PKCS1v15`` padding. All other key types **must**
            not pass a value other than ``None``.

    .. method:: add_certificate(certificate)

        Add an additional certificate (typically used to help build a
        verification chain) to the PKCS7 structure. This method may
        be called multiple times to add as many certificates as desired.

        :param certificate: The :class:`~cryptography.x509.Certificate` to add.

    .. method:: sign(encoding, options)

        :param encoding: :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`,
            or :attr:`~cryptography.hazmat.primitives.serialization.Encoding.SMIME`.

        :param options: A list of
            :class:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7Options`.

        :returns bytes: The signed PKCS7 message.


.. function:: pkcs7_verify_der(data, content=None, certificate=None, options=None)

    .. versionadded:: 45.0.0

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import hashes, serialization
        >>> from cryptography.hazmat.primitives.serialization import pkcs7
        >>> cert = x509.load_pem_x509_certificate(verify_cert)
        >>> key = serialization.load_pem_private_key(verify_key, None)
        >>> signed = pkcs7.PKCS7SignatureBuilder().set_data(
        ...     b"data to sign"
        ... ).add_signer(
        ...     cert, key, hashes.SHA256()
        ... ).sign(
        ...     serialization.Encoding.DER, []
        ... )
        >>> pkcs7.pkcs7_verify_der(signed)

    Deserialize and verify a DER-encoded PKCS7 signed message. PKCS7 (or S/MIME) has multiple
    versions, but this supports a subset of :rfc:`5751`, also known as S/MIME Version 3.2. If the
    verification succeeds, does not return anything. If the verification fails, raises an exception.

    :param data: The data, encoded in DER format.
    :type data: bytes

    :param content: if specified, the content to verify against the signed message. If the content
        is not specified, the function will look for the content in the signed message. Defaults to
        None.
    :type content: bytes or None

    :param certificate: if specified, a :class:`~cryptography.x509.Certificate` to verify against
        the signed message. If None, the function will look for the signer certificate in the signed
        message. Defaults to None.
    :type certificate: :class:`~cryptography.x509.Certificate` or None
    
    :raises ValueError: If the recipient certificate does not match any of the signers in the
        PKCS7 data.
    
    :raises ValueError: If no content is specified and no content is found in the PKCS7 data.

    :raises ValueError: If the PKCS7 data is not of the signed data type.


.. function:: pkcs7_verify_pem(data, content=None, certificate=None, options=None)

    .. versionadded:: 45.0.0

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import hashes, serialization
        >>> from cryptography.hazmat.primitives.serialization import pkcs7
        >>> cert = x509.load_pem_x509_certificate(verify_cert)
        >>> key = serialization.load_pem_private_key(verify_key, None)
        >>> signed = pkcs7.PKCS7SignatureBuilder().set_data(
        ...     b"data to sign"
        ... ).add_signer(
        ...     cert, key, hashes.SHA256()
        ... ).sign(
        ...     serialization.Encoding.PEM, []
        ... )
        >>> pkcs7.pkcs7_verify_pem(signed)

    Deserialize and verify a PEM-encoded PKCS7 signed message. PKCS7 (or S/MIME) has multiple
    versions, but this supports a subset of :rfc:`5751`, also known as S/MIME Version 3.2. If the
    verification succeeds, does not return anything. If the verification fails, raises an exception.

    :param data: The data, encoded in PEM format.
    :type data: bytes

    :param content: if specified, the content to verify against the signed message. If the content
        is not specified, the function will look for the content in the signed message. Defaults to
        None.
    :type content: bytes or None

    :param certificate: if specified, a :class:`~cryptography.x509.Certificate` to verify against
        the signed message. If None, the function will look for the signer certificate in the signed
        message. Defaults to None.
    :type certificate: :class:`~cryptography.x509.Certificate` or None

    :raises ValueError: If the PEM data does not have the PKCS7 tag.
    
    :raises ValueError: If the recipient certificate does not match any of the signers in the
        PKCS7 data.
    
    :raises ValueError: If no content is specified and no content is found in the PKCS7 data.

    :raises ValueError: If the PKCS7 data is not of the signed data type.


.. function:: pkcs7_verify_smime(data, content=None, certificate=None, options=None)

    .. versionadded:: 45.0.0

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import hashes, serialization
        >>> from cryptography.hazmat.primitives.serialization import pkcs7
        >>> cert = x509.load_pem_x509_certificate(verify_cert)
        >>> key = serialization.load_pem_private_key(verify_key, None)
        >>> signed = pkcs7.PKCS7SignatureBuilder().set_data(
        ...     b"data to sign"
        ... ).add_signer(
        ...     cert, key, hashes.SHA256()
        ... ).sign(
        ...     serialization.Encoding.SMIME, []
        ... )
        >>> pkcs7.pkcs7_verify_smime(signed)

    Verify a PKCS7 signed message stored in a MIME message, by reading it, extracting the content
    (if any) and signature, deserializing the signature and verifying it against the content. PKCS7
    (or S/MIME) has multiple versions, but this supports a subset of :rfc:`5751`, also known as
    S/MIME Version 3.2. If the verification succeeds, does not return anything. If the verification
    fails, raises an exception.  

    :param data: The data, encoded in MIME format.
    :type data: bytes

    :param content: if specified, the content to verify against the signed message. If the content
        is not specified, the function will look for the content in the MIME message and in the
        signature. Defaults to None.
    :type content: bytes or None

    :param certificate: if specified, a :class:`~cryptography.x509.Certificate` to verify against
        the signed message. If None, the function will look for the signer certificate in the signed
        message. Defaults to None.
    :type certificate: :class:`~cryptography.x509.Certificate` or None

    :raises ValueError: If the MIME message is not a S/MIME signed message: content type is
        different than ``multipart/signed`` or ``application/pkcs7-mime``.
    
    :raises ValueError: If the MIME message is a malformed ``multipart/signed`` S/MIME message: not
        multipart, or multipart with more than 2 parts (content & signature).
    
    :raises ValueError: If the recipient certificate does not match any of the signers in the
        PKCS7 data.
    
    :raises ValueError: If no content is specified and no content is found in the PKCS7 data.

    :raises ValueError: If the PKCS7 data is not of the signed data type.

.. class:: PKCS7EnvelopeBuilder

    The PKCS7 envelope builder can create encrypted S/MIME messages,
    which are commonly used in email. S/MIME has multiple versions,
    but this implements a subset of :rfc:`5751`, also known as S/MIME
    Version 3.2.

    .. versionadded:: 43.0.0

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import serialization
        >>> from cryptography.hazmat.primitives.serialization import pkcs7
        >>> from cryptography.hazmat.primitives.ciphers import algorithms
        >>> cert = x509.load_pem_x509_certificate(ca_cert_rsa)
        >>> options = [pkcs7.PKCS7Options.Text]
        >>> pkcs7.PKCS7EnvelopeBuilder().set_data(
        ...     b"data to encrypt"
        ... ).set_content_encryption_algorithm(
        ...     algorithms.AES128
        ... ).add_recipient(
        ...     cert
        ... ).encrypt(
        ...     serialization.Encoding.SMIME, options
        ... )
        b'...'

    .. method:: set_data(data)

        :param data: The data to be encrypted.
        :type data: :term:`bytes-like`

    .. method:: set_content_encryption_algorithm(content_encryption_algorithm)

        :param content_encryption_algorithm: the content encryption algorithm to use.
            Only AES is supported, with a key size of 128 or 256 bits.
        :type content_encryption_algorithm:
            :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES128`
            or :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES256`

    .. method:: add_recipient(certificate)

        Add a recipient for the message. Recipients will be able to use their private keys
        to decrypt the message. This method may be called multiple times to add as many recipients
        as desired.

        :param certificate: A :class:`~cryptography.x509.Certificate` for an intended
            recipient of the encrypted message. Only certificates with public RSA keys
            are currently supported.

    .. method:: encrypt(encoding, options)

        The message is encrypted using AES-128-CBC. The encryption key used is included in
        the envelope, encrypted using the recipient's public RSA key. If multiple recipients
        are specified, the key is encrypted once with each recipient's public key, and all
        encrypted keys are included in the envelope (one per recipient).

        :param encoding: :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`,
            or :attr:`~cryptography.hazmat.primitives.serialization.Encoding.SMIME`.

        :param options: A list of
            :class:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7Options`. For
            this operation only
            :attr:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7Options.Text` and
            :attr:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7Options.Binary`
            are supported, and cannot be used at the same time.

        :returns bytes: The enveloped PKCS7 message.

.. function:: pkcs7_decrypt_der(data, certificate, private_key, options)

    .. versionadded:: 44.0.0

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import serialization
        >>> from cryptography.hazmat.primitives.serialization import pkcs7
        >>> cert = x509.load_pem_x509_certificate(ca_cert_rsa)
        >>> key = serialization.load_pem_private_key(ca_key_rsa, None)
        >>> options = [pkcs7.PKCS7Options.Text]
        >>> enveloped = pkcs7.PKCS7EnvelopeBuilder().set_data(
        ...     b"data to encrypt"
        ... ).add_recipient(
        ...     cert
        ... ).encrypt(
        ...     serialization.Encoding.DER, options
        ... )
        >>> pkcs7.pkcs7_decrypt_der(enveloped, cert, key, options)
        b'data to encrypt'

    Deserialize and decrypt a DER-encoded PKCS7 message. PKCS7 (or S/MIME) has multiple versions,
    but this supports a subset of :rfc:`5751`, also known as S/MIME Version 3.2.

    :param data: The data, encoded in DER format.
    :type data: bytes

    :param certificate: A :class:`~cryptography.x509.Certificate` for an intended
        recipient of the encrypted message. Only certificates with public RSA keys
        are currently supported.

    :param private_key: The :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
        associated with the certificate provided. Only private RSA keys are supported.

    :param options: A list of
        :class:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7Options`. For
        this operation only
        :attr:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7Options.Text` is supported.

    :returns bytes: The decrypted message.

    :raises ValueError: If the recipient certificate does not match any of the encrypted keys in the
        PKCS7 data.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If any of the PKCS7 keys are encrypted
        with another algorithm than RSA with PKCS1 v1.5 padding.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the content is encrypted with
        another algorithm than AES (with key sizes 128 and 256), with CBC mode.

    :raises ValueError: If the PKCS7 data does not contain encrypted content.

    :raises ValueError: If the PKCS7 data is not of the enveloped data type.

.. function:: pkcs7_decrypt_pem(data, certificate, private_key, options)

    .. versionadded:: 44.0.0

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import serialization
        >>> from cryptography.hazmat.primitives.serialization import pkcs7
        >>> cert = x509.load_pem_x509_certificate(ca_cert_rsa)
        >>> key = serialization.load_pem_private_key(ca_key_rsa, None)
        >>> options = [pkcs7.PKCS7Options.Text]
        >>> enveloped = pkcs7.PKCS7EnvelopeBuilder().set_data(
        ...     b"data to encrypt"
        ... ).add_recipient(
        ...     cert
        ... ).encrypt(
        ...     serialization.Encoding.PEM, options
        ... )
        >>> pkcs7.pkcs7_decrypt_pem(enveloped, cert, key, options)
        b'data to encrypt'

    Deserialize and decrypt a PEM-encoded PKCS7E message. PKCS7 (or S/MIME) has multiple versions,
    but this supports a subset of :rfc:`5751`, also known as S/MIME Version 3.2.

    :param data: The data, encoded in PEM format.
    :type data: bytes

    :param certificate: A :class:`~cryptography.x509.Certificate` for an intended
        recipient of the encrypted message. Only certificates with public RSA keys
        are currently supported.

    :param private_key: The :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
        associated with the certificate provided. Only private RSA keys are supported.

    :param options: A list of
        :class:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7Options`. For
        this operation only
        :attr:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7Options.Text` is supported.

    :returns bytes: The decrypted message.

    :raises ValueError: If the PEM data does not have the PKCS7 tag.

    :raises ValueError: If the recipient certificate does not match any of the encrypted keys in the
        PKCS7 data.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If any of the PKCS7 keys are encrypted
        with another algorithm than RSA with PKCS1 v1.5 padding.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the content is encrypted with
        another algorithm than AES (with key sizes 128 and 256), with CBC mode.

    :raises ValueError: If the PKCS7 data does not contain encrypted content.

    :raises ValueError: If the PKCS7 data is not of the enveloped data type.

.. function:: pkcs7_decrypt_smime(data, certificate, private_key, options)

    .. versionadded:: 44.0.0

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import serialization
        >>> from cryptography.hazmat.primitives.serialization import pkcs7
        >>> cert = x509.load_pem_x509_certificate(ca_cert_rsa)
        >>> key = serialization.load_pem_private_key(ca_key_rsa, None)
        >>> options = [pkcs7.PKCS7Options.Text]
        >>> enveloped = pkcs7.PKCS7EnvelopeBuilder().set_data(
        ...     b"data to encrypt"
        ... ).add_recipient(
        ...     cert
        ... ).encrypt(
        ...     serialization.Encoding.SMIME, options
        ... )
        >>> pkcs7.pkcs7_decrypt_smime(enveloped, cert, key, options)
        b'data to encrypt'

    Deserialize and decrypt a S/MIME-encoded PKCS7 message. PKCS7 (or S/MIME) has multiple versions,
    but this supports a subset of :rfc:`5751`, also known as S/MIME Version 3.2.

    :param data: The data. It should be in S/MIME format, meaning MIME with content type
        ``application/pkcs7-mime`` or ``application/x-pkcs7-mime``.
    :type data: bytes

    :param certificate: A :class:`~cryptography.x509.Certificate` for an intended
        recipient of the encrypted message. Only certificates with public RSA keys
        are currently supported.

    :param private_key: The :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
        associated with the certificate provided. Only private RSA keys are supported.

    :param options: A list of
        :class:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7Options`. For
        this operation only
        :attr:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7Options.Text` is supported.

    :returns bytes: The decrypted message.

    :raises ValueError: If the S/MIME data is not one of the correct content types.

    :raises ValueError: If the recipient certificate does not match any of the encrypted keys in the
        PKCS7 data.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If any of the PKCS7 keys are encrypted
        with another algorithm than RSA with PKCS1 v1.5 padding.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the content is encrypted with
        another algorithm than AES (with key sizes 128 and 256), with CBC mode.

    :raises ValueError: If the PKCS7 data does not contain encrypted content.

    :raises ValueError: If the PKCS7 data is not of the enveloped data type.


.. class:: PKCS7Options

    .. versionadded:: 3.2

    An enumeration of options for PKCS7 signature, envelope creation, and decryption.

    .. attribute:: Text

        For signing, the text option adds ``text/plain`` headers to an S/MIME message when
        serializing to
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.SMIME`.
        This option is disallowed with ``DER`` serialization.
        For envelope creation, it adds ``text/plain`` headers to the encrypted content, regardless
        of the specified encoding.
        For envelope decryption, it parses the decrypted content headers (if any), checks if the
        content type is 'text/plain', then removes all headers (keeping only the payload) of this
        decrypted content. If there is no header, or the content type is not "text/plain", it
        raises an error.

    .. attribute:: Binary

        Signature and envelope creation normally converts line endings (LF to CRLF). When
        passing this option, the data will not be converted.

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
    :canonical: cryptography.hazmat.primitives._serialization.PrivateFormat

    .. versionadded:: 0.8

    An enumeration for private key formats. Used with the ``private_bytes``
    method available on
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
    ,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
    , :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`
    and
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.

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

        A raw format used by :doc:`/hazmat/primitives/asymmetric/ed25519`,
        :doc:`/hazmat/primitives/asymmetric/ed448`,
        :doc:`/hazmat/primitives/asymmetric/x25519`, and
        :doc:`/hazmat/primitives/asymmetric/x448`. It is a
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

    .. attribute:: PKCS12

        .. versionadded:: 38.0.0

        The PKCS#12 format is a binary format used to store private keys and
        certificates. This attribute is used in conjunction with
        ``encryption_builder()`` to allow control of the encryption algorithm
        and parameters.

        .. doctest::

            >>> from cryptography.hazmat.primitives import hashes
            >>> from cryptography.hazmat.primitives.serialization import PrivateFormat, pkcs12
            >>> encryption = (
            ...     PrivateFormat.PKCS12.encryption_builder().
            ...     kdf_rounds(50000).
            ...     key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC).
            ...     hmac_hash(hashes.SHA256()).build(b"my password")
            ... )
            >>> p12 = pkcs12.serialize_key_and_certificates(
            ...     b"friendlyname", key, None, None, encryption
            ... )

    .. method:: encryption_builder()

        .. versionadded:: 38.0.0

        Returns a builder for configuring how values are encrypted with this
        format. You must call this method on an element of the enumeration.
        For example, ``PrivateFormat.OpenSSH.encryption_builder()``.

        For most use cases, :class:`BestAvailableEncryption` is preferred.

        :returns: A new instance of :class:`KeySerializationEncryptionBuilder`

        .. doctest::

            >>> from cryptography.hazmat.primitives import serialization
            >>> encryption = (
            ...     serialization.PrivateFormat.OpenSSH.encryption_builder().kdf_rounds(30).build(b"my password")
            ... )
            >>> key.private_bytes(
            ...     encoding=serialization.Encoding.PEM,
            ...     format=serialization.PrivateFormat.OpenSSH,
            ...     encryption_algorithm=encryption
            ... )
            b'-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----\n'


.. class:: PublicFormat

    .. versionadded:: 0.8

    An enumeration for public key formats. Used with the ``public_bytes``
    method available on
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`
    ,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
    , :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`
    , and
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`.

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

        A raw format used by :doc:`/hazmat/primitives/asymmetric/ed25519`,
        :doc:`/hazmat/primitives/asymmetric/ed448`,
        :doc:`/hazmat/primitives/asymmetric/x25519`, and
        :doc:`/hazmat/primitives/asymmetric/x448`. It is a
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
    :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`.

    .. attribute:: PKCS3

        ASN1 DH parameters sequence as defined in `PKCS3`_.

Serialization Encodings
~~~~~~~~~~~~~~~~~~~~~~~

.. class:: Encoding
    :canonical: cryptography.hazmat.primitives._serialization.Encoding

    An enumeration for encoding types. Used with the ``private_bytes`` method
    available on
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
    ,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
    , :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`,
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

        A raw format used by :doc:`/hazmat/primitives/asymmetric/ed25519`,
        :doc:`/hazmat/primitives/asymmetric/ed448`,
        :doc:`/hazmat/primitives/asymmetric/x25519`, and
        :doc:`/hazmat/primitives/asymmetric/x448`. It is a
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
    :canonical: cryptography.hazmat.primitives._serialization.KeySerializationEncryption

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
    :canonical: cryptography.hazmat.primitives._serialization.BestAvailableEncryption

    Encrypt using the best available encryption for a given key.
    This is a curated encryption choice and the algorithm may change over
    time. The encryption algorithm may vary based on which version of OpenSSL
    the library is compiled against.

    :param bytes password: The password to use for encryption.

.. class:: NoEncryption
    :canonical: cryptography.hazmat.primitives._serialization.NoEncryption

    Do not encrypt.


.. class:: KeySerializationEncryptionBuilder

    .. versionadded:: 38.0.0

    A builder that can be used to configure how data is encrypted. To
    create one, call :meth:`PrivateFormat.encryption_builder`. Different
    serialization types will support different options on this builder.

    .. method:: kdf_rounds(rounds)

        Set the number of rounds the Key Derivation Function should use. The
        meaning of the number of rounds varies on the KDF being used.

        :param int rounds: Number of rounds.

    .. method:: key_cert_algorithm(algorithm)

        Set the encryption algorithm to use when encrypting the key and
        certificate in a PKCS12 structure.

        :param algorithm: A value from the :class:`~cryptography.hazmat.primitives.serialization.pkcs12.PBES`
            enumeration.

    .. method:: hmac_hash(algorithm)

        Set the hash algorithm to use within the MAC for a PKCS12 structure.

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`

    .. method:: build(password)

        Turns the builder into an instance of
        :class:`KeySerializationEncryption` with a given password.

        :param bytes password: The password.
        :returns: A :class:`KeySerializationEncryption` encryption object
            that can be passed to methods like ``private_bytes`` or
            :func:`~cryptography.hazmat.primitives.serialization.pkcs12.serialize_key_and_certificates`.

.. _`a bug in Firefox`: https://bugzilla.mozilla.org/show_bug.cgi?id=773111
.. _`PKCS3`: https://www.teletrust.de/fileadmin/files/oid/oid_pkcs-3v1-4.pdf
.. _`SEC 1 v2.0`: https://www.secg.org/sec1-v2.pdf
.. _`PROTOCOL.key`: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
.. _`PROTOCOL.certkeys`: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
