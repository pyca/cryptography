.. hazmat::

RSA
===

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.rsa

`RSA`_ is a `public-key`_ algorithm for encrypting and signing messages.

Generation
~~~~~~~~~~

.. function:: generate_private_key(public_exponent, key_size, backend)

    .. versionadded:: 0.5

    Generate an RSA private key using the provided ``backend``.

    :param int public_exponent: The public exponent of the new key.
        Usually one of the small Fermat primes 3, 5, 17, 257, 65537. If in
        doubt you should `use 65537`_.
    :param int key_size: The length of the modulus in bits. For keys
        generated in 2014 it is strongly recommended to be
        `at least 2048`_ (See page 41). It must not be less than 512.
        Some backends may have additional limitations.
    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.RSABackend`
        provider.
    :return: A :class:`~cryptography.hazmat.primitives.interfaces.RSAPrivateKey`
        provider.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if
        the provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.RSABackend`

Signing
~~~~~~~

Using a :class:`~cryptography.hazmat.primitives.interfaces.RSAPrivateKey`
provider.

.. doctest::

    >>> from cryptography.hazmat.backends import default_backend
    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.primitives.asymmetric import rsa, padding
    >>> private_key = rsa.generate_private_key(
    ...     public_exponent=65537,
    ...     key_size=2048,
    ...     backend=default_backend()
    ... )
    >>> signer = private_key.signer(
    ...     padding.PSS(
    ...         mgf=padding.MGF1(hashes.SHA256()),
    ...         salt_length=padding.PSS.MAX_LENGTH
    ...     ),
    ...     hashes.SHA256()
    ... )
    >>> signer.update(b"this is some data I'd like")
    >>> signer.update(b" to sign")
    >>> signature = signer.finalize()


Verification
~~~~~~~~~~~~

Using a :class:`~cryptography.hazmat.primitives.interfaces.RSAPublicKey`
provider.

.. doctest::

    >>> public_key = private_key.public_key()
    >>> verifier = public_key.verifier(
    ...     signature,
    ...     padding.PSS(
    ...         mgf=padding.MGF1(hashes.SHA256()),
    ...         salt_length=padding.PSS.MAX_LENGTH
    ...     ),
    ...     hashes.SHA256()
    ... )
    >>> data = b"this is some data I'd like to sign"
    >>> verifier.update(data)
    >>> verifier.verify()

Encryption
~~~~~~~~~~

Using a :class:`~cryptography.hazmat.primitives.interfaces.RSAPublicKey`
provider.

.. doctest::

    >>> from cryptography.hazmat.backends import default_backend
    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.primitives.asymmetric import padding

    >>> # Generate a key
    >>> private_key = rsa.generate_private_key(
    ...     public_exponent=65537,
    ...     key_size=2048,
    ...     backend=default_backend()
    ... )
    >>> public_key = private_key.public_key()
    >>> # encrypt some data
    >>> ciphertext = public_key.encrypt(
    ...     b"encrypted data",
    ...     padding.OAEP(
    ...         mgf=padding.MGF1(algorithm=hashes.SHA1()),
    ...         algorithm=hashes.SHA1(),
    ...         label=None
    ...     )
    ... )

Decryption
~~~~~~~~~~

Using a :class:`~cryptography.hazmat.primitives.interfaces.RSAPrivateKey`
provider.

.. doctest::

    >>> plaintext = private_key.decrypt(
    ...     ciphertext,
    ...     padding.OAEP(
    ...         mgf=padding.MGF1(algorithm=hashes.SHA1()),
    ...         algorithm=hashes.SHA1(),
    ...         label=None
    ...     )
    ... )

Padding
~~~~~~~

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.padding

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

.. class:: OAEP(mgf, label)

    .. versionadded:: 0.4

    OAEP (Optimal Asymmetric Encryption Padding) is a padding scheme defined in
    :rfc:`3447`. It provides probabilistic encryption and is `proven secure`_
    against several attack types. This is the `recommended padding algorithm`_
    for RSA encryption. It cannot be used with RSA signing.

    :param mgf: A mask generation function object. At this time the only
        supported MGF is :class:`MGF1`.

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

Mask generation functions
-------------------------

.. class:: MGF1(algorithm)

    .. versionadded:: 0.3

    .. versionchanged:: 0.6
        Removed the deprecated ``salt_length`` parameter.

    MGF1 (Mask Generation Function 1) is used as the mask generation function
    in :class:`PSS` padding. It takes a hash algorithm and a salt length.

    :param algorithm: An instance of a
        :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
        provider.

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

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.RSABackend`
            provider.

        :returns: A new instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.RSAPublicKey`
            provider.

.. class:: RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, public_numbers)

    .. versionadded:: 0.5

    The collection of integers that make up an RSA private key.

    .. warning::

        With the exception of the integers contained in the
        :class:`RSAPublicNumbers` all attributes of this class must be kept
        secret. Revealing them will compromise the security of any
        cryptographic operations performed with a key loaded from them.

    .. attribute:: public_numbers

        :type: :class:`~cryptography.hazmat.primitives.rsa.RSAPublicNumbers`

        The :class:`RSAPublicNumbers` which makes up the RSA public key
        associated with this RSA private key.

    .. attribute:: p

        :type: int

        ``p``, one of the two primes composing the :attr:`modulus`.

    .. attribute:: q

        :type: int

        ``q``, one of the two primes composing the :attr:`modulus`.

    .. attribute:: d

        :type: int

        The private exponent. Alias for :attr:`private_exponent`.

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

        :param backend: A new instance of a
            :class:`~cryptography.hazmat.backends.interfaces.RSABackend`
            provider.

        :returns: A
            :class:`~cryptography.hazmat.primitives.interfaces.RSAPrivateKey`
            provider.

Handling partial RSA private keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you are trying to load RSA private keys yourself you may find that not all
parameters required by ``RSAPrivateNumbers`` are available. In particular the
`Chinese Remainder Theorem`_ (CRT) values ``dmp1``, ``dmq1``, ``iqmp`` may be
missing or present in a different form. For example `OpenPGP`_ does not include
the ``iqmp``, ``dmp1`` or ``dmq1`` parameters.

The following functions are provided for users who want to work with keys like
this without having to do the math themselves.

.. function:: rsa_crt_iqmp(p, q)

    .. versionadded:: 0.4

    Generates the ``iqmp`` (also known as ``qInv``) parameter from the RSA
    primes ``p`` and ``q``.

.. function:: rsa_crt_dmp1(private_exponent, p)

    .. versionadded:: 0.4

    Generates the ``dmp1`` parameter from the RSA private exponent and prime
    ``p``.

.. function:: rsa_crt_dmq1(private_exponent, q)

    .. versionadded:: 0.4

    Generates the ``dmq1`` parameter from the RSA private exponent and prime
    ``q``.


.. _`RSA`: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
.. _`public-key`: https://en.wikipedia.org/wiki/Public-key_cryptography
.. _`use 65537`: http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
.. _`at least 2048`: http://www.ecrypt.eu.org/documents/D.SPA.20.pdf
.. _`OpenPGP`: https://en.wikipedia.org/wiki/Pretty_Good_Privacy
.. _`Chinese Remainder Theorem`: https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29#Using_the_Chinese_remainder_algorithm
.. _`security proof`: http://eprint.iacr.org/2001/062.pdf
.. _`recommended padding algorithm`: http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
.. _`proven secure`: http://cseweb.ucsd.edu/users/mihir/papers/oae.pdf
