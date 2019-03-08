.. hazmat::

Backend interfaces
==================

.. currentmodule:: cryptography.hazmat.backends.interfaces


Backend implementations may provide a number of interfaces to support
operations such as :doc:`/hazmat/primitives/symmetric-encryption`,
:doc:`/hazmat/primitives/cryptographic-hashes`, and
:doc:`/hazmat/primitives/mac/hmac`.

A specific ``backend`` may provide one or more of these interfaces.


.. class:: CipherBackend

    A backend that provides methods for using ciphers for encryption
    and decryption.

    The following backends implement this interface:

    * :doc:`/hazmat/backends/openssl`

    .. method:: cipher_supported(cipher, mode)

        Check if a ``cipher`` and ``mode`` combination is supported by
        this backend.

        :param cipher: An instance of
            :class:`~cryptography.hazmat.primitives.ciphers.CipherAlgorithm`.

        :param mode: An instance of
            :class:`~cryptography.hazmat.primitives.ciphers.modes.Mode`.

        :returns: ``True`` if the specified ``cipher`` and ``mode`` combination
            is supported by this backend, otherwise ``False``


    .. method:: create_symmetric_encryption_ctx(cipher, mode)

        Create a
        :class:`~cryptography.hazmat.primitives.ciphers.CipherContext` that
        can be used for encrypting data with the symmetric ``cipher`` using
        the given ``mode``.

        :param cipher: An instance of
            :class:`~cryptography.hazmat.primitives.ciphers.CipherAlgorithm`.

        :param mode: An instance of
            :class:`~cryptography.hazmat.primitives.ciphers.modes.Mode`.

        :returns:
            :class:`~cryptography.hazmat.primitives.ciphers.CipherContext`

        :raises ValueError: When tag is not None in an AEAD mode


    .. method:: create_symmetric_decryption_ctx(cipher, mode)

        Create a
        :class:`~cryptography.hazmat.primitives.ciphers.CipherContext` that
        can be used for decrypting data with the symmetric ``cipher`` using
        the given ``mode``.

        :param cipher: An instance of
            :class:`~cryptography.hazmat.primitives.ciphers.CipherAlgorithm`.

        :param mode: An instance of
            :class:`~cryptography.hazmat.primitives.ciphers.modes.Mode`.

        :returns:
            :class:`~cryptography.hazmat.primitives.ciphers.CipherContext`

        :raises ValueError: When tag is None in an AEAD mode


.. class:: HashBackend

    A backend with methods for using cryptographic hash functions.

    The following backends implement this interface:

    * :doc:`/hazmat/backends/openssl`

    .. method:: hash_supported(algorithm)

        Check if the specified ``algorithm`` is supported by this backend.

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

        :returns: ``True`` if the specified ``algorithm`` is supported by this
            backend, otherwise ``False``.


    .. method:: create_hash_ctx(algorithm)

        Create a
        :class:`~cryptography.hazmat.primitives.hashes.HashContext` that
        uses the specified ``algorithm`` to calculate a message digest.

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

        :returns:
            :class:`~cryptography.hazmat.primitives.hashes.HashContext`


.. class:: HMACBackend

    A backend with methods for using cryptographic hash functions as message
    authentication codes.

    The following backends implement this interface:

    * :doc:`/hazmat/backends/openssl`

    .. method:: hmac_supported(algorithm)

        Check if the specified ``algorithm`` is supported by this backend.

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

        :returns: ``True`` if the specified ``algorithm`` is supported for HMAC
            by this backend, otherwise ``False``.

    .. method:: create_hmac_ctx(key, algorithm)

        Create a
        :class:`~cryptography.hazmat.primitives.hashes.HashContext` that
        uses the specified ``algorithm`` to calculate a hash-based message
        authentication code.

        :param bytes key: Secret key as ``bytes``.

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

        :returns:
            :class:`~cryptography.hazmat.primitives.hashes.HashContext`


.. class:: CMACBackend

    .. versionadded:: 0.4

    A backend with methods for using CMAC

    .. method:: cmac_algorithm_supported(algorithm)

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.ciphers.BlockCipherAlgorithm`.

        :return: Returns True if the block cipher is supported for CMAC by this backend

    .. method:: create_cmac_ctx(algorithm)

        Create a
        context that
        uses the specified ``algorithm`` to calculate a message authentication code.

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.ciphers.BlockCipherAlgorithm`.

        :returns: CMAC object.


.. class:: PBKDF2HMACBackend

    .. versionadded:: 0.2

    A backend with methods for using PBKDF2 using HMAC as a PRF.

    The following backends implement this interface:

    * :doc:`/hazmat/backends/openssl`

    .. method:: pbkdf2_hmac_supported(algorithm)

        Check if the specified ``algorithm`` is supported by this backend.

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

        :returns: ``True`` if the specified ``algorithm`` is supported for
            PBKDF2 HMAC by this backend, otherwise ``False``.

    .. method:: derive_pbkdf2_hmac(self, algorithm, length, salt, iterations, key_material)

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

        :param int length: The desired length of the derived key. Maximum is
            (2\ :sup:`32` - 1) * ``algorithm.digest_size``

        :param bytes salt: A salt.

        :param int iterations: The number of iterations to perform of the hash
            function. This can be used to control the length of time the
            operation takes. Higher numbers help mitigate brute force attacks
            against derived keys.

        :param bytes key_material: The key material to use as a basis for
            the derived key. This is typically a password.

        :return bytes: Derived key.


.. class:: RSABackend

    .. versionadded:: 0.2

    A backend with methods for using RSA.

    .. method:: generate_rsa_private_key(public_exponent, key_size)

        :param int public_exponent: The public exponent of the new key.
            Often one of the small Fermat primes 3, 5, 17, 257 or 65537.

        :param int key_size: The length in bits of the modulus. Should be
            at least 2048.

        :return: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`.

        :raises ValueError: If the public_exponent is not valid.

    .. method:: rsa_padding_supported(padding)

        Check if the specified ``padding`` is supported by the backend.

        :param padding: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.padding.AsymmetricPadding`.

        :returns: ``True`` if the specified ``padding`` is supported by this
            backend, otherwise ``False``.

    .. method:: generate_rsa_parameters_supported(public_exponent, key_size)

        Check if the specified parameters are supported for key generation by
        the backend.

        :param int public_exponent: The public exponent.

        :param int key_size: The bit length of the generated modulus.

    .. method:: load_rsa_private_numbers(numbers)

        :param numbers: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateNumbers`.

        :returns: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`.

        :raises ValueError: This is raised when the values of ``p``, ``q``,
            ``private_exponent``, ``public_exponent``, or ``modulus`` do not
            match the bounds specified in :rfc:`3447`.

        :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised
            when any backend specific criteria are not met.

    .. method:: load_rsa_public_numbers(numbers)

        :param numbers: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers`.

        :returns: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`.

        :raises ValueError: This is raised when the values of
            ``public_exponent`` or ``modulus`` do not match the bounds
            specified in :rfc:`3447`.

        :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised
            when any backend specific criteria are not met.


.. class:: DSABackend

    .. versionadded:: 0.4

    A backend with methods for using DSA.

    .. method:: generate_dsa_parameters(key_size)

        :param int key_size: The length of the modulus in bits. It should be
            either 1024, 2048 or 3072. For keys generated in 2015 this should
            be at least 2048.
            Note that some applications (such as SSH) have not yet gained
            support for larger key sizes specified in FIPS 186-3 and are still
            restricted to only the 1024-bit keys specified in FIPS 186-2.

        :return: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`.

    .. method:: generate_dsa_private_key(parameters)

        :param parameters: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`.

        :return: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.

        :raises ValueError: This is raised if the key size is not one of 1024,
            2048, or 3072.

    .. method:: generate_dsa_private_key_and_parameters(key_size)

        :param int key_size: The length of the modulus in bits. It should be
            either 1024, 2048 or 3072. For keys generated in 2015 this should
            be at least 2048.
            Note that some applications (such as SSH) have not yet gained
            support for larger key sizes specified in FIPS 186-3 and are still
            restricted to only the 1024-bit keys specified in FIPS 186-2.

        :return: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.

        :raises ValueError: This is raised if the key size is not supported
            by the backend.

    .. method:: dsa_hash_supported(algorithm)

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

        :returns: ``True`` if the specified ``algorithm`` is supported by this
            backend, otherwise ``False``.

    .. method:: dsa_parameters_supported(p, q, g)

        :param int p: The p value of a DSA key.

        :param int q: The q value of a DSA key.

        :param int g: The g value of a DSA key.

        :returns: ``True`` if the given values of ``p``, ``q``, and ``g`` are
            supported by this backend, otherwise ``False``.

    .. method:: load_dsa_parameter_numbers(numbers)

        :param numbers: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameterNumbers`.

        :returns: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`.

        :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised
            when any backend specific criteria are not met.

    .. method:: load_dsa_private_numbers(numbers)

        :param numbers: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateNumbers`.

        :returns: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.

        :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised
            when any backend specific criteria are not met.

    .. method:: load_dsa_public_numbers(numbers)

        :param numbers: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicNumbers`.

        :returns: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`.

        :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised
            when any backend specific criteria are not met.


.. class:: EllipticCurveBackend

    .. versionadded:: 0.5

    .. method:: elliptic_curve_supported(curve)

        :param curve: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve`.

        :returns: True if the elliptic curve is supported by this backend.

    .. method:: elliptic_curve_signature_algorithm_supported(signature_algorithm, curve)

        :param signature_algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurveSignatureAlgorithm`.

        :param curve: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve`.

        :returns: True if the signature algorithm and curve are supported by this backend.

    .. method:: generate_elliptic_curve_private_key(curve)

        :param curve: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve`.

    .. method:: load_elliptic_curve_private_numbers(numbers)

        :param numbers: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateNumbers`.

        :returns: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`.

    .. method:: load_elliptic_curve_public_numbers(numbers)

        :param numbers: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers`.

        :returns: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`.

    .. method:: derive_elliptic_curve_private_key(private_value, curve)

        :param private_value: A secret scalar value.

        :param curve: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve`.

        :returns: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`.

.. class:: PEMSerializationBackend

    .. versionadded:: 0.6

    A backend with methods for working with any PEM encoded keys.

    .. method:: load_pem_private_key(data, password)

        :param bytes data: PEM data to load.
        :param bytes password: The password to use if the data is encrypted.
            Should be ``None`` if the data is not encrypted.
        :return: A new instance of the appropriate type of private key that the
            serialized data contains.
        :raises ValueError: If the data could not be deserialized.
        :raises cryptography.exceptions.UnsupportedAlgorithm: If the data is
            encrypted with an unsupported algorithm.

    .. method:: load_pem_public_key(data)

        :param bytes data: PEM data to load.
        :return: A new instance of the appropriate type of public key
            serialized data contains.
        :raises ValueError: If the data could not be deserialized.

    .. method:: load_pem_parameters(data)

        .. versionadded:: 2.0

        :param bytes data: PEM data to load.
        :return: A new instance of the appropriate type of asymmetric
            parameters the serialized data contains.
        :raises ValueError: If the data could not be deserialized.

.. class:: DERSerializationBackend

    .. versionadded:: 0.8

    A backend with methods for working with DER encoded keys.

    .. method:: load_der_private_key(data, password)

        :param bytes data: DER data to load.
        :param bytes password: The password to use if the data is encrypted.
            Should be ``None`` if the data is not encrypted.
        :return: A new instance of the appropriate type of private key that the
            serialized data contains.
        :raises ValueError: If the data could not be deserialized.
        :raises cryptography.exceptions.UnsupportedAlgorithm: If the data is
            encrypted with an unsupported algorithm.

    .. method:: load_der_public_key(data)

        :param bytes data: DER data to load.
        :return: A new instance of the appropriate type of public key
            serialized data contains.
        :raises ValueError: If the data could not be deserialized.

    .. method:: load_der_parameters(data)

        .. versionadded:: 2.0

        :param bytes data: DER data to load.
        :return: A new instance of the appropriate type of asymmetric
            parameters the serialized data contains.
        :raises ValueError: If the data could not be deserialized.


.. class:: X509Backend

    .. versionadded:: 0.7

    A backend with methods for working with X.509 objects.

    .. method:: load_pem_x509_certificate(data)

        :param bytes data: PEM formatted certificate data.

        :returns: An instance of :class:`~cryptography.x509.Certificate`.

    .. method:: load_der_x509_certificate(data)

        :param bytes data: DER formatted certificate data.

        :returns: An instance of :class:`~cryptography.x509.Certificate`.

    .. method:: load_pem_x509_csr(data)

        .. versionadded:: 0.9

        :param bytes data: PEM formatted certificate signing request data.

        :returns: An instance of
            :class:`~cryptography.x509.CertificateSigningRequest`.

    .. method:: load_der_x509_csr(data)

        .. versionadded:: 0.9

        :param bytes data: DER formatted certificate signing request data.

        :returns: An instance of
            :class:`~cryptography.x509.CertificateSigningRequest`.

    .. method:: create_x509_csr(builder, private_key, algorithm)

        .. versionadded:: 1.0

        :param builder: An instance of
            :class:`~cryptography.x509.CertificateSigningRequestBuilder`.

        :param private_key: The
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey` or
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
            that will be used to sign the request.  When the request is
            signed by a certificate authority, the private key's associated
            public key will be stored in the resulting certificate.

        :param algorithm: The
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            that will be used to generate the request signature.

        :returns: A new instance of
            :class:`~cryptography.x509.CertificateSigningRequest`.

    .. method:: create_x509_certificate(builder, private_key, algorithm)

        .. versionadded:: 1.0

        :param builder: An instance of
            :class:`~cryptography.x509.CertificateBuilder`.

        :param private_key: The
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey` or
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
            that will be used to sign the certificate.

        :param algorithm: The
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            that will be used to generate the certificate signature.

        :returns: A new instance of :class:`~cryptography.x509.Certificate`.

    .. method:: create_x509_crl(builder, private_key, algorithm)

        .. versionadded:: 1.2

        :param builder: An instance of
            :class:`~cryptography.x509.CertificateRevocationListBuilder`.

        :param private_key: The
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey` or
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
            that will be used to sign the CRL.

        :param algorithm: The
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            that will be used to generate the CRL signature.

        :returns: A new instance of
            :class:`~cryptography.x509.CertificateRevocationList`.

    .. method:: create_x509_revoked_certificate(builder)

        .. versionadded:: 1.2

        :param builder: An instance of RevokedCertificateBuilder.

        :returns: A new instance of
            :class:`~cryptography.x509.RevokedCertificate`.

    .. method:: x509_name_bytes(name)

        .. versionadded:: 1.6

        :param name: An instance of :class:`~cryptography.x509.Name`.

        :return bytes: The DER encoded bytes.

.. class:: DHBackend

    .. versionadded:: 0.9

    A backend with methods for doing Diffie-Hellman key exchange.

    .. method:: generate_dh_parameters(generator, key_size)

        :param int generator: The generator to use. Often 2 or 5.

        :param int key_size: The bit length of the prime modulus to generate.

        :return: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`.

        :raises ValueError: If ``key_size`` is not at least 512.

    .. method:: generate_dh_private_key(parameters)

        :param parameters: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`.

        :return: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`.

    .. method:: generate_dh_private_key_and_parameters(generator, key_size)

        :param int generator: The generator to use. Often 2 or 5.

        :param int key_size: The bit length of the prime modulus to generate.

        :return: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`.

        :raises ValueError: If ``key_size`` is not at least 512.

    .. method:: load_dh_private_numbers(numbers)

        :param numbers: A
            :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateNumbers`
            instance.

        :return: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`.

        :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised
            when any backend specific criteria are not met.

    .. method:: load_dh_public_numbers(numbers)

        :param numbers: A
            :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicNumbers`
            instance.

        :return: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`.

        :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised
            when any backend specific criteria are not met.

    .. method:: load_dh_parameter_numbers(numbers)

        :param numbers: A
            :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameterNumbers`
            instance.

        :return: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`.

        :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised
            when any backend specific criteria are not met.

    .. method:: dh_parameters_supported(p, g, q=None)

        :param int p: The p value of the DH key.

        :param int g: The g value of the DH key.

        :param int q: The q value of the DH key.

        :returns: ``True`` if the given values of ``p``, ``g`` and ``q``
            are supported by this backend, otherwise ``False``.

    .. versionadded:: 1.8

    .. method:: dh_x942_serialization_supported()

        :returns: True if serialization of DH objects with
            subgroup order (q) is supported by this backend.


.. class:: ScryptBackend

    .. versionadded:: 1.6

    A backend with methods for using Scrypt.

    The following backends implement this interface:

    * :doc:`/hazmat/backends/openssl`

    .. method:: derive_scrypt(self, key_material, salt, length, n, r, p)

        :param bytes key_material: The key material to use as a basis for
            the derived key. This is typically a password.

        :param bytes salt: A salt.

        :param int length: The desired length of the derived key.

        :param int n: CPU/Memory cost parameter. It must be larger than 1 and be a
            power of 2.

        :param int r: Block size parameter.

        :param int p: Parallelization parameter.

        :return bytes: Derived key.

