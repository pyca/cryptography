.. hazmat::

RSA
===

.. module:: cryptography.hazmat.primitives.asymmetric.rsa

`RSA`_ is a `public-key`_ algorithm for encrypting and signing messages.

Generation
~~~~~~~~~~

Unlike symmetric cryptography, where the key is typically just a random series
of bytes, RSA keys have a complex internal structure with `specific
mathematical properties`_.

.. function:: generate_private_key(public_exponent, key_size, backend)

    .. versionadded:: 0.5

    Generates a new RSA private key using the provided ``backend``.
    ``key_size`` describes how many :term:`bits` long the key should be. Larger
    keys provide more security; currently ``1024`` and below are considered
    breakable while ``2048`` or ``4096`` are reasonable default key sizes for
    new keys. The ``public_exponent`` indicates what one mathematical property
    of the key generation will be. Unless you have a specific reason to do
    otherwise, you should always `use 65537`_.

    .. doctest::

        >>> from cryptography.hazmat.backends import default_backend
        >>> from cryptography.hazmat.primitives.asymmetric import rsa
        >>> private_key = rsa.generate_private_key(
        ...     public_exponent=65537,
        ...     key_size=2048,
        ...     backend=default_backend()
        ... )

    :param int public_exponent: The public exponent of the new key.
        Usually one of the small Fermat primes 3, 5, 17, 257, 65537. If in
        doubt you should `use 65537`_.

    :param int key_size: The length of the modulus in :term:`bits`. For keys
        generated in 2015 it is strongly recommended to be
        `at least 2048`_ (See page 41). It must not be less than 512.
        Some backends may have additional limitations.

    :param backend: A backend which implements
        :class:`~cryptography.hazmat.backends.interfaces.RSABackend`.

    :return: An instance of
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if
        the provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.RSABackend`

Key loading
~~~~~~~~~~~

If you already have an on-disk key in the PEM format (which are recognizable by
the distinctive ``-----BEGIN {format}-----`` and ``-----END {format}-----``
markers), you can load it:

.. code-block:: pycon

    >>> from cryptography.hazmat.backends import default_backend
    >>> from cryptography.hazmat.primitives import serialization

    >>> with open("path/to/key.pem", "rb") as key_file:
    ...     private_key = serialization.load_pem_private_key(
    ...         key_file.read(),
    ...         password=None,
    ...         backend=default_backend()
    ...     )

Serialized keys may optionally be encrypted on disk using a password. In this
example we loaded an unencrypted key, and therefore we did not provide a
password. If the key is encrypted we can pass a ``bytes`` object as the
``password`` argument.

There is also support for :func:`loading public keys in the SSH format
<cryptography.hazmat.primitives.serialization.load_ssh_public_key>`.

Key serialization
~~~~~~~~~~~~~~~~~

If you have a private key that you've loaded or generated which implements the
:class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`
interface you can use
:meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.private_bytes`
to serialize the key.

.. doctest::

    >>> from cryptography.hazmat.primitives import serialization
    >>> pem = private_key.private_bytes(
    ...    encoding=serialization.Encoding.PEM,
    ...    format=serialization.PrivateFormat.PKCS8,
    ...    encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
    ... )
    >>> pem.splitlines()[0]
    b'-----BEGIN ENCRYPTED PRIVATE KEY-----'

It is also possible to serialize without encryption using
:class:`~cryptography.hazmat.primitives.serialization.NoEncryption`.

.. doctest::

    >>> pem = private_key.private_bytes(
    ...    encoding=serialization.Encoding.PEM,
    ...    format=serialization.PrivateFormat.TraditionalOpenSSL,
    ...    encryption_algorithm=serialization.NoEncryption()
    ... )
    >>> pem.splitlines()[0]
    b'-----BEGIN RSA PRIVATE KEY-----'

For public keys you can use
:meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.public_bytes`
to serialize the key.

.. doctest::

    >>> from cryptography.hazmat.primitives import serialization
    >>> public_key = private_key.public_key()
    >>> pem = public_key.public_bytes(
    ...    encoding=serialization.Encoding.PEM,
    ...    format=serialization.PublicFormat.SubjectPublicKeyInfo
    ... )
    >>> pem.splitlines()[0]
    b'-----BEGIN PUBLIC KEY-----'

Signing
~~~~~~~

A private key can be used to sign a message. This allows anyone with the public
key to verify that the message was created by someone who possesses the
corresponding private key. RSA signatures require a specific hash function, and
padding to be used. Here is an example of signing ``message`` using RSA, with a
secure hash function and padding:

.. doctest::

    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.primitives.asymmetric import padding
    >>> message = b"A message I want to sign"
    >>> signature = private_key.sign(
    ...     message,
    ...     padding.PSS(
    ...         mgf=padding.MGF1(hashes.SHA256()),
    ...         salt_length=padding.PSS.MAX_LENGTH
    ...     ),
    ...     hashes.SHA256()
    ... )

Valid paddings for signatures are
:class:`~cryptography.hazmat.primitives.asymmetric.padding.PSS` and
:class:`~cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15`. ``PSS``
is the recommended choice for any new protocols or applications, ``PKCS1v15``
should only be used to support legacy protocols.

If your data is too large to be passed in a single call, you can hash it
separately and pass that value using
:class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`.

.. doctest::

    >>> from cryptography.hazmat.primitives.asymmetric import utils
    >>> chosen_hash = hashes.SHA256()
    >>> hasher = hashes.Hash(chosen_hash, default_backend())
    >>> hasher.update(b"data & ")
    >>> hasher.update(b"more data")
    >>> digest = hasher.finalize()
    >>> sig = private_key.sign(
    ...     digest,
    ...     padding.PSS(
    ...         mgf=padding.MGF1(hashes.SHA256()),
    ...         salt_length=padding.PSS.MAX_LENGTH
    ...     ),
    ...     utils.Prehashed(chosen_hash)
    ... )

Verification
~~~~~~~~~~~~

The previous section describes what to do if you have a private key and want to
sign something. If you have a public key, a message, a signature, and the
signing algorithm that was used you can check that the private key associated
with a given public key was used to sign that specific message.  You can obtain
a public key to use in verification using
:func:`~cryptography.hazmat.primitives.serialization.load_pem_public_key`,
:func:`~cryptography.hazmat.primitives.serialization.load_der_public_key`,
:meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers.public_key`
, or
:meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.public_key`.

.. doctest::

    >>> public_key = private_key.public_key()
    >>> public_key.verify(
    ...     signature,
    ...     message,
    ...     padding.PSS(
    ...         mgf=padding.MGF1(hashes.SHA256()),
    ...         salt_length=padding.PSS.MAX_LENGTH
    ...     ),
    ...     hashes.SHA256()
    ... )

If the signature does not match, ``verify()`` will raise an
:class:`~cryptography.exceptions.InvalidSignature` exception.

If your data is too large to be passed in a single call, you can hash it
separately and pass that value using
:class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`.

.. doctest::

    >>> chosen_hash = hashes.SHA256()
    >>> hasher = hashes.Hash(chosen_hash, default_backend())
    >>> hasher.update(b"data & ")
    >>> hasher.update(b"more data")
    >>> digest = hasher.finalize()
    >>> public_key.verify(
    ...     sig,
    ...     digest,
    ...     padding.PSS(
    ...         mgf=padding.MGF1(hashes.SHA256()),
    ...         salt_length=padding.PSS.MAX_LENGTH
    ...     ),
    ...     utils.Prehashed(chosen_hash)
    ... )

Encryption
~~~~~~~~~~

RSA encryption is interesting because encryption is performed using the
**public** key, meaning anyone can encrypt data. The data is then decrypted
using the **private** key.

Like signatures, RSA supports encryption with several different padding
options. Here's an example using a secure padding and hash function:

.. doctest::

    >>> message = b"encrypted data"
    >>> ciphertext = public_key.encrypt(
    ...     message,
    ...     padding.OAEP(
    ...         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    ...         algorithm=hashes.SHA256(),
    ...         label=None
    ...     )
    ... )

Valid paddings for encryption are
:class:`~cryptography.hazmat.primitives.asymmetric.padding.OAEP` and
:class:`~cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15`. ``OAEP``
is the recommended choice for any new protocols or applications, ``PKCS1v15``
should only be used to support legacy protocols.


Decryption
~~~~~~~~~~

Once you have an encrypted message, it can be decrypted using the private key:

.. doctest::

    >>> plaintext = private_key.decrypt(
    ...     ciphertext,
    ...     padding.OAEP(
    ...         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    ...         algorithm=hashes.SHA256(),
    ...         label=None
    ...     )
    ... )
    >>> plaintext == message
    True

Padding
~~~~~~~

.. module:: cryptography.hazmat.primitives.asymmetric.padding

.. class:: AsymmetricPadding

    .. versionadded:: 0.2

    .. attribute:: name

.. class:: PSS(mgf, salt_length)

    .. versionadded:: 0.3

    .. versionchanged:: 0.4
        Added ``salt_length`` parameter.

    PSS (Probabilistic Signature Scheme) is a signature scheme defined in
    :rfc:`3447`. It is more complex than PKCS1 but possesses a `security proof`_.
    This is the `recommended padding algorithm`_ for RSA signatures. It cannot
    be used with RSA encryption.

    :param mgf: A mask generation function object. At this time the only
        supported MGF is :class:`MGF1`.

    :param int salt_length: The length of the salt. It is recommended that this
        be set to ``PSS.MAX_LENGTH``.

    .. attribute:: MAX_LENGTH

        Pass this attribute to ``salt_length`` to get the maximum salt length
        available.

.. class:: OAEP(mgf, algorithm, label)

    .. versionadded:: 0.4

    OAEP (Optimal Asymmetric Encryption Padding) is a padding scheme defined in
    :rfc:`3447`. It provides probabilistic encryption and is `proven secure`_
    against several attack types. This is the `recommended padding algorithm`_
    for RSA encryption. It cannot be used with RSA signing.

    :param mgf: A mask generation function object. At this time the only
        supported MGF is :class:`MGF1`.

    :param algorithm: An instance of
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

    :param bytes label: A label to apply. This is a rarely used field and
        should typically be set to ``None`` or ``b""``, which are equivalent.

.. class:: PKCS1v15()

    .. versionadded:: 0.3

    PKCS1 v1.5 (also known as simply PKCS1) is a simple padding scheme
    developed for use with RSA keys. It is defined in :rfc:`3447`. This padding
    can be used for signing and encryption.

    It is not recommended that ``PKCS1v15`` be used for new applications,
    :class:`OAEP` should be preferred for encryption and :class:`PSS` should be
    preferred for signatures.


.. function:: calculate_max_pss_salt_length(key, hash_algorithm)

    .. versionadded:: 1.5

    :param key: An RSA public or private key.
    :param hash_algorithm: A
        :class:`cryptography.hazmat.primitives.hashes.HashAlgorithm`.
    :returns int: The computed salt length.

    Computes the length of the salt that :class:`PSS` will use if
    :data:`PSS.MAX_LENGTH` is used.


Mask generation functions
-------------------------

.. class:: MGF1(algorithm)

    .. versionadded:: 0.3

    .. versionchanged:: 0.6
        Removed the deprecated ``salt_length`` parameter.

    MGF1 (Mask Generation Function 1) is used as the mask generation function
    in :class:`PSS` and :class:`OAEP` padding. It takes a hash algorithm.

    :param algorithm: An instance of
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

Numbers
~~~~~~~

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.rsa

These classes hold the constituent components of an RSA key. They are useful
only when more traditional :doc:`/hazmat/primitives/asymmetric/serialization`
is unavailable.

.. class:: RSAPublicNumbers(e, n)

    .. versionadded:: 0.5

    The collection of integers that make up an RSA public key.

    .. attribute:: n

        :type: int

        The public modulus.

    .. attribute:: e

        :type: int

        The public exponent.

    .. method:: public_key(backend)

        :param backend: An instance of
            :class:`~cryptography.hazmat.backends.interfaces.RSABackend`.

        :returns: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`.

.. class:: RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, public_numbers)

    .. versionadded:: 0.5

    The collection of integers that make up an RSA private key.

    .. warning::

        With the exception of the integers contained in the
        :class:`RSAPublicNumbers` all attributes of this class must be kept
        secret. Revealing them will compromise the security of any
        cryptographic operations performed with a key loaded from them.

    .. attribute:: public_numbers

        :type: :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers`

        The :class:`RSAPublicNumbers` which makes up the RSA public key
        associated with this RSA private key.

    .. attribute:: p

        :type: int

        ``p``, one of the two primes composing ``n``.

    .. attribute:: q

        :type: int

        ``q``, one of the two primes composing ``n``.

    .. attribute:: d

        :type: int

        The private exponent.

    .. attribute:: dmp1

        :type: int

        A `Chinese remainder theorem`_ coefficient used to speed up RSA
        operations. Calculated as: d mod (p-1)

    .. attribute:: dmq1

        :type: int

        A `Chinese remainder theorem`_ coefficient used to speed up RSA
        operations. Calculated as: d mod (q-1)

    .. attribute:: iqmp

        :type: int

        A `Chinese remainder theorem`_ coefficient used to speed up RSA
        operations. Calculated as: q\ :sup:`-1` mod p

    .. method:: private_key(backend)

        :param backend: A new instance of
            :class:`~cryptography.hazmat.backends.interfaces.RSABackend`.

        :returns: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`.

Handling partial RSA private keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you are trying to load RSA private keys yourself you may find that not all
parameters required by ``RSAPrivateNumbers`` are available. In particular the
`Chinese Remainder Theorem`_ (CRT) values ``dmp1``, ``dmq1``, ``iqmp`` may be
missing or present in a different form. For example, `OpenPGP`_ does not include
the ``iqmp``, ``dmp1`` or ``dmq1`` parameters.

The following functions are provided for users who want to work with keys like
this without having to do the math themselves.

.. function:: rsa_crt_iqmp(p, q)

    .. versionadded:: 0.4

    Computes the ``iqmp`` (also known as ``qInv``) parameter from the RSA
    primes ``p`` and ``q``.

.. function:: rsa_crt_dmp1(private_exponent, p)

    .. versionadded:: 0.4

    Computes the ``dmp1`` parameter from the RSA private exponent (``d``) and
    prime ``p``.

.. function:: rsa_crt_dmq1(private_exponent, q)

    .. versionadded:: 0.4

    Computes the ``dmq1`` parameter from the RSA private exponent (``d``) and
    prime ``q``.

.. function:: rsa_recover_prime_factors(n, e, d)

    .. versionadded:: 0.8

    Computes the prime factors ``(p, q)`` given the modulus, public exponent,
    and private exponent.

    .. note::

        When recovering prime factors this algorithm will always return ``p``
        and ``q`` such that ``p > q``. Note: before 1.5, this function always
        returned ``p`` and ``q`` such that ``p < q``. It was changed because
        libraries commonly require ``p > q``.

    :return: A tuple ``(p, q)``


Key interfaces
~~~~~~~~~~~~~~

.. class:: RSAPrivateKey

    .. versionadded:: 0.2

    An `RSA`_ private key. An RSA private key that is not an
    :term:`opaque key` also implements :class:`RSAPrivateKeyWithSerialization`
    to provide serialization methods.

    .. method:: decrypt(ciphertext, padding)

        .. versionadded:: 0.4

        Decrypt data that was encrypted with the public key.

        :param bytes ciphertext: The ciphertext to decrypt.

        :param padding: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.padding.AsymmetricPadding`.

        :return bytes: Decrypted data.

    .. method:: public_key()

        :return: :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`

        An RSA public key object corresponding to the values of the private key.

    .. attribute:: key_size

        :type: int

        The bit length of the modulus.

    .. method:: sign(data, padding, algorithm)

        .. versionadded:: 1.4
        .. versionchanged:: 1.6
            :class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`
            can now be used as an ``algorithm``.

        Sign one block of data which can be verified later by others using the
        public key.

        :param bytes data: The message string to sign.

        :param padding: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.padding.AsymmetricPadding`.

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` or
            :class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`
            if the ``data`` you want to sign has already been hashed.

        :return bytes: Signature.


.. class:: RSAPrivateKeyWithSerialization

    .. versionadded:: 0.8

    This interface contains additional methods relating to serialization.
    Any object with this interface also has all the methods from
    :class:`RSAPrivateKey`.

    .. method:: private_numbers()

        Create a
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateNumbers`
        object.

        :returns: An
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateNumbers`
            instance.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM` or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`),
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL`
        or
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8`)
        and encryption algorithm (such as
        :class:`~cryptography.hazmat.primitives.serialization.BestAvailableEncryption`
        or :class:`~cryptography.hazmat.primitives.serialization.NoEncryption`)
        are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PrivateFormat`
            enum.

        :param encryption_algorithm: An instance of an object conforming to the
            :class:`~cryptography.hazmat.primitives.serialization.KeySerializationEncryption`
            interface.

        :return bytes: Serialized key.


.. class:: RSAPublicKey

    .. versionadded:: 0.2

    An `RSA`_ public key.

    .. method:: encrypt(plaintext, padding)

        .. versionadded:: 0.4

        Encrypt data with the public key.

        :param bytes plaintext: The plaintext to encrypt.

        :param padding: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.padding.AsymmetricPadding`.

        :return bytes: Encrypted data.

    .. attribute:: key_size

        :type: int

        The bit length of the modulus.

    .. method:: public_numbers()

        Create a
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers`
        object.

        :returns: An
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers`
            instance.

    .. method:: public_bytes(encoding, format)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM` or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo`
        or
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.PKCS1`)
        are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PublicFormat` enum.

        :return bytes: Serialized key.

    .. method:: verify(signature, data, padding, algorithm)

        .. versionadded:: 1.4
        .. versionchanged:: 1.6
            :class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`
            can now be used as an ``algorithm``.

        Verify one block of data was signed by the private key
        associated with this public key.

        :param bytes signature: The signature to verify.

        :param bytes data: The message string that was signed.

        :param padding: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.padding.AsymmetricPadding`.

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` or
            :class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`
            if the ``data`` you want to verify has already been hashed.

        :raises cryptography.exceptions.InvalidSignature: If the signature does
            not validate.


.. class:: RSAPublicKeyWithSerialization

    .. versionadded:: 0.8

    Alias for :class:`RSAPublicKey`.


.. _`RSA`: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
.. _`public-key`: https://en.wikipedia.org/wiki/Public-key_cryptography
.. _`specific mathematical properties`: https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
.. _`use 65537`: http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
.. _`at least 2048`: http://www.ecrypt.eu.org/ecrypt2/documents/D.SPA.20.pdf
.. _`OpenPGP`: https://en.wikipedia.org/wiki/Pretty_Good_Privacy
.. _`Chinese Remainder Theorem`: https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29#Using_the_Chinese_remainder_algorithm
.. _`security proof`: https://eprint.iacr.org/2001/062.pdf
.. _`recommended padding algorithm`: http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
.. _`proven secure`: https://cseweb.ucsd.edu/~mihir/papers/oae.pdf
