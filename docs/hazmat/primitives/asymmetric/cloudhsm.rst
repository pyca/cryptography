.. hazmat::

Cloud KMS and HSM Asymmetric Keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. testsetup::

    """
    We need to have this exist so the doctest below allows us to
    test that we're satisfying the base class requirements.
    """
    class Response:
        def __init__(self, signature):
            self.signature = signature

    class SomeCloudClient:
        def __init__(self, creds):
            pass

        def sign(self, key_id, algorithm, message):
            return Response(b"\x00" * (self.key_size(key_id) // 8))

        def key_size(self, key_id):
            return 2048

``cryptography`` provides a set of abstract base classes for asymmetric keys
that can be used to integrate with cloud key management services, HSMs, and other ways of managing keys that are not in-memory.
A minimal example with a hypothetical cloud key management service for an RSA
key is provided below, but this works for all asymmetric types. You must provide
all methods of the base class, but many methods can be stubs with no implementation
if you only need a subset of functionality.

.. doctest::

    >>> import typing
    >>> from cryptography.hazmat.primitives.asymmetric import rsa, utils
    >>> from cryptography.hazmat.primitives import hashes, serialization
    >>> from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding, PKCS1v15
    >>>
    >>> class CloudRSAPrivateKey(rsa.RSAPrivateKey):
    ...     def __init__(self, creds, key_id):
    ...         self._creds = creds
    ...         self._cloud_client = SomeCloudClient(creds)
    ...         self._key_id = key_id
    ...
    ...     def sign(
    ...         self,
    ...         data: bytes,
    ...         padding: AsymmetricPadding,
    ...         algorithm: typing.Union[utils.Prehashed, hashes.HashAlgorithm],
    ...     ) -> bytes:
    ...         """
    ...         Signs data using the cloud KMS. You'll need to define a mapping
    ...         between the way your cloud provider represents padding and algorithms
    ...         and the way cryptography represents them.
    ...         """
    ...
    ...         # Hash the data if necessary
    ...         if not isinstance(algorithm, utils.Prehashed):
    ...             h = hashes.Hash(algorithm)
    ...             h.update(data)
    ...             digest = h.finalize()
    ...             hash_alg = algorithm
    ...         else:
    ...             digest = data
    ...             hash_alg = algorithm._algorithm
    ...         # Map cryptography padding/algorithm to KMS signing algorithm
    ...         kms_algorithm = self._map_to_kms_algorithm(padding, hash_alg)
    ...
    ...         # Call KMS API to sign the digest
    ...         response = self._cloud_client.sign(
    ...             key_id=self._key_id,
    ...             algorithm=kms_algorithm,
    ...             message=digest,
    ...         )
    ...
    ...         return response.signature
    ...
    ...     def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
    ...         raise NotImplementedError()
    ...
    ...     def _map_to_kms_algorithm(
    ...         self,
    ...         padding: AsymmetricPadding,
    ...         algorithm: hashes.HashAlgorithm
    ...     ) -> bytes:
    ...         """
    ...         Maps the cryptography padding and algorithm to the corresponding KMS signing algorithm.
    ...         This is specific to your implementation.
    ...         """
    ...         if isinstance(padding, PKCS1v15) and isinstance(algorithm, hashes.SHA256):
    ...             return b"RSA_PKCS1_V1_5_SHA_256"
    ...         else:
    ...             raise NotImplementedError()
    ...
    ...     @property
    ...     def key_size(self) -> int:
    ...         return self._cloud_client.key_size(self._key_id)
    ...
    ...     def public_key(self) -> rsa.RSAPublicKey:
    ...         raise NotImplementedError()
    ...
    ...     def private_numbers(self) -> rsa.RSAPrivateNumbers:
    ...         """
    ...         This method typically can't be implemented for cloud KMS keys
    ...         as the private key material is not accessible.
    ...         """
    ...         raise NotImplementedError()
    ...
    ...     def private_bytes(
    ...         self,
    ...         encoding: serialization.Encoding,
    ...         format: serialization.PrivateFormat,
    ...         encryption_algorithm: serialization.KeySerializationEncryption,
    ...     ) -> bytes:
    ...         """
    ...         This method typically can't be implemented for cloud KMS keys
    ...         as the private key material is not accessible.
    ...         """
    ...         raise NotImplementedError()
    ...
    ...     def __copy__(self) -> "CloudRSAPrivateKey":
    ...         return self
    ...
    >>> cloud_private_key = CloudRSAPrivateKey("creds", "key_id")
    >>> sig = cloud_private_key.sign(b"message", PKCS1v15(), hashes.SHA256())
    >>> isinstance(sig, bytes)
    True

This key can then be used with other parts of ``cryptography``, such as the X.509 APIs.
In the example below we assume that we are using our cloud private key to sign
a leaf certificate (not self-signed).

.. doctest::

        >>> from cryptography import x509
        >>> from cryptography.x509.oid import NameOID
        >>> import datetime
        >>> one_day = datetime.timedelta(1, 0, 0)
        >>> leaf_private_key = rsa.generate_private_key(
        ...     public_exponent=65537,
        ...     key_size=2048,
        ... )
        >>> leaf_public_key = leaf_private_key.public_key()
        >>> builder = x509.CertificateBuilder()
        >>> builder = builder.subject_name(x509.Name([
        ...     x509.NameAttribute(NameOID.COMMON_NAME, 'cryptography.io'),
        ... ]))
        >>> builder = builder.issuer_name(x509.Name([
        ...     x509.NameAttribute(NameOID.COMMON_NAME, 'My Cloud CA'),
        ... ]))
        >>> builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        >>> builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
        >>> builder = builder.serial_number(x509.random_serial_number())
        >>> builder = builder.public_key(leaf_public_key)
        >>> builder = builder.add_extension(
        ...     x509.SubjectAlternativeName(
        ...         [x509.DNSName('cryptography.io')]
        ...     ),
        ...     critical=False
        ... )
        >>> builder = builder.add_extension(
        ...     x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ... )
        >>> certificate = builder.sign(
        ...     private_key=cloud_private_key, algorithm=hashes.SHA256(),
        ... )
        >>> isinstance(certificate, x509.Certificate)
        True
