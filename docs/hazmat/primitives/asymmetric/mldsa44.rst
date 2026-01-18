.. hazmat::

ML-DSA-44 signing
=================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.mldsa44


ML-DSA-44 is a post-quantum digital signature algorithm based on module
lattices, standardized in `FIPS 204`_. It provides NIST security level 2
(comparable to 128-bit security) and is suitable for applications where smaller
key and signature sizes are important. ML-DSA-44 is designed to be secure
against attacks from both classical and quantum computers.

Signing & Verification
~~~~~~~~~~~~~~~~~~~~~~~

.. doctest::

    >>> from cryptography.hazmat.primitives.asymmetric.mldsa44 import MlDsa44PrivateKey
    >>> private_key = MlDsa44PrivateKey.generate()
    >>> signature = private_key.sign(b"my authenticated message")
    >>> public_key = private_key.public_key()
    >>> # Raises InvalidSignature if verification fails
    >>> public_key.verify(signature, b"my authenticated message")

Context-based Signing & Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ML-DSA-44 supports context strings to bind additional information to signatures.
The context can be up to 255 bytes and is used to differentiate signatures in
different contexts or protocols. This is useful for domain separation and
preventing cross-protocol attacks.

.. doctest::

    >>> from cryptography.hazmat.primitives.asymmetric.mldsa44 import MlDsa44PrivateKey
    >>> private_key = MlDsa44PrivateKey.generate()
    >>> context = b"email-signature-v1"
    >>> signature = private_key.sign_with_context(b"my authenticated message", context)
    >>> public_key = private_key.public_key()
    >>> # Verification requires the same context
    >>> public_key.verify_with_context(signature, b"my authenticated message", context)

X.509 Certificate Usage
~~~~~~~~~~~~~~~~~~~~~~~~

ML-DSA-44 can be used to create and sign X.509 certificates. When signing
certificates with ML-DSA, the ``hash_algorithm`` parameter must be ``None``
as ML-DSA uses pure signature mode without pre-hashing.

.. doctest::

    >>> import datetime
    >>> from cryptography import x509
    >>> from cryptography.x509.oid import NameOID
    >>> from cryptography.hazmat.primitives.asymmetric import mldsa44
    >>> from cryptography.hazmat.primitives import serialization
    >>> # Generate ML-DSA-44 key
    >>> private_key = mldsa44.MlDsa44PrivateKey.generate()
    >>> public_key = private_key.public_key()
    >>> # Create a self-signed certificate
    >>> subject = issuer = x509.Name([
    ...     x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ...     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
    ...     x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ... ])
    >>> cert = (
    ...     x509.CertificateBuilder()
    ...     .subject_name(subject)
    ...     .issuer_name(issuer)
    ...     .public_key(public_key)
    ...     .serial_number(x509.random_serial_number())
    ...     .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    ...     .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    ...     .sign(private_key, None)  # hash_algorithm must be None for ML-DSA
    ... )
    >>> # Verify the certificate signature
    >>> cert_public_key = cert.public_key()
    >>> cert_public_key.verify(cert.signature, cert.tbs_certificate_bytes)

CMS/PKCS#7 Signed Data
~~~~~~~~~~~~~~~~~~~~~~~

ML-DSA-44 can be used to create CMS (Cryptographic Message Syntax) signed
messages, commonly used for S/MIME email and document signing.

.. doctest::

    >>> from cryptography.hazmat.primitives.serialization import pkcs7
    >>> # Create a signed message
    >>> message = b"Important document content"
    >>> builder = (
    ...     pkcs7.PKCS7SignatureBuilder()
    ...     .set_data(message)
    ...     .add_signer(cert, private_key, None)  # hash_algorithm must be None for ML-DSA
    ... )
    >>> # Sign and serialize as PEM
    >>> signed_data = builder.sign(serialization.Encoding.PEM, [])
    >>> # The signed_data can now be transmitted and verified by recipients

.. note::
    When using ML-DSA with CMS, the ``hash_algorithm`` parameter must be
    ``None``. This is required by RFC 9882. The digestAlgorithm field in
    the CMS structure will automatically use SHA-512 for compliance with
    the standard.

Key interfaces
~~~~~~~~~~~~~~

.. class:: MlDsa44PrivateKey

    .. versionadded:: 47.0

    .. classmethod:: generate()

        Generate an ML-DSA-44 private key.

        :returns: :class:`MlDsa44PrivateKey`

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-DSA-44 is
            not supported by the OpenSSL version ``cryptography`` is using.

    .. classmethod:: from_seed_bytes(data)

        A class method for deterministically generating an ML-DSA-44 private key
        from seed bytes. This is used for deterministic key generation, not for
        loading serialized keys. To load serialized private keys, use
        :func:`~cryptography.hazmat.primitives.serialization.load_pem_private_key`
        or :func:`~cryptography.hazmat.primitives.serialization.load_der_private_key`.

        :param data: 32 byte seed.
        :type data: :term:`bytes-like`

        :returns: :class:`MlDsa44PrivateKey`

        :raises ValueError: If the seed is not 32 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-DSA-44 is
            not supported by the OpenSSL version ``cryptography`` is using.

        .. doctest::

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import mldsa44
            >>> private_key = mldsa44.MlDsa44PrivateKey.generate()
            >>> # Serialize to PEM
            >>> pem = private_key.private_bytes(
            ...     encoding=serialization.Encoding.PEM,
            ...     format=serialization.PrivateFormat.PKCS8,
            ...     encryption_algorithm=serialization.NoEncryption()
            ... )
            >>> # Load from PEM
            >>> loaded_private_key = serialization.load_pem_private_key(pem, password=None)


    .. method:: public_key()

        :returns: :class:`MlDsa44PublicKey`

    .. method:: sign(data)

        Sign the data using ML-DSA-44.

        :param data: The data to sign.
        :type data: :term:`bytes-like`

        :returns bytes: The signature (2420 bytes).

    .. method:: sign_with_context(data, context)

        Sign the data using ML-DSA-44 with an additional context string.
        The context is used for domain separation and preventing cross-protocol
        attacks.

        :param data: The data to sign.
        :type data: :term:`bytes-like`

        :param context: The context string (up to 255 bytes).
        :type context: :term:`bytes-like`

        :returns bytes: The signature (2420 bytes).

        :raises ValueError: If the context is longer than 255 bytes.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`, or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8`
        or
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
        ) are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PrivateFormat`
            enum. If the ``encoding`` is
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
            then ``format`` must be
            :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
            , otherwise it must be
            :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8`.

        :param encryption_algorithm: An instance of an object conforming to the
            :class:`~cryptography.hazmat.primitives.serialization.KeySerializationEncryption`
            interface.

        :return bytes: Serialized key.

    .. method:: seed_bytes()

        Returns the 32-byte seed used to generate this private key. This seed
        can be used with :meth:`from_seed_bytes` to deterministically recreate
        the same private key.

        :return bytes: 32-byte seed.

        .. doctest::

            >>> from cryptography.hazmat.primitives.asymmetric import mldsa44
            >>> private_key = mldsa44.MlDsa44PrivateKey.generate()
            >>> seed = private_key.seed_bytes()
            >>> len(seed)
            32
            >>> # Recreate the same key from the seed
            >>> recreated_key = mldsa44.MlDsa44PrivateKey.from_seed_bytes(seed)

.. class:: MlDsa44PublicKey

    .. versionadded:: 47.0

    .. classmethod:: from_public_bytes(data)

        :param bytes data: 1312 byte public key.

        :returns: :class:`MlDsa44PublicKey`

        :raises ValueError: If the public key is not 1312 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-DSA-44 is
            not supported by the OpenSSL version ``cryptography`` is using.

        .. doctest::

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import mldsa44
            >>> private_key = mldsa44.MlDsa44PrivateKey.generate()
            >>> public_key = private_key.public_key()
            >>> public_bytes = public_key.public_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PublicFormat.Raw
            ... )
            >>> loaded_public_key = mldsa44.MlDsa44PublicKey.from_public_bytes(public_bytes)

    .. method:: public_bytes(encoding, format)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`, or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo`
        or
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
        ) are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PublicFormat`
            enum. If the ``encoding`` is
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
            then ``format`` must be
            :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
            , otherwise it must be
            :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo`.

        :returns bytes: The public key bytes.

    .. method:: public_bytes_raw()

        Allows serialization of the key to raw bytes. This method is a
        convenience shortcut for calling :meth:`public_bytes` with
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
        encoding and
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
        format.

        :return bytes: 1312-byte raw public key.

    .. method:: verify(signature, data)

        Verify a signature using ML-DSA-44.

        :param signature: The signature to verify.
        :type signature: :term:`bytes-like`

        :param data: The data to verify.
        :type data: :term:`bytes-like`

        :returns: None
        :raises cryptography.exceptions.InvalidSignature: Raised when the
            signature cannot be verified.

    .. method:: verify_with_context(signature, data, context)

        Verify a signature using ML-DSA-44 with the context string that was used
        during signing. The same context must be provided for verification to
        succeed.

        :param signature: The signature to verify.
        :type signature: :term:`bytes-like`

        :param data: The data to verify.
        :type data: :term:`bytes-like`

        :param context: The context string (up to 255 bytes) that was used during signing.
        :type context: :term:`bytes-like`

        :returns: None
        :raises cryptography.exceptions.InvalidSignature: Raised when the
            signature cannot be verified.
        :raises ValueError: If the context is longer than 255 bytes.


.. _`FIPS 204`: https://csrc.nist.gov/pubs/fips/204/final
