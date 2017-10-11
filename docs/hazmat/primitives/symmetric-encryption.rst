.. hazmat:: /fernet


Symmetric encryption
====================

.. module:: cryptography.hazmat.primitives.ciphers

Symmetric encryption is a way to `encrypt`_ or hide the contents of material
where the sender and receiver both use the same secret key. Note that symmetric
encryption is **not** sufficient for most applications because it only
provides secrecy but not authenticity. That means an attacker can't see the
message but an attacker can create bogus messages and force the application to
decrypt them.

For this reason it is **strongly** recommended to combine encryption with a
message authentication code, such as :doc:`HMAC </hazmat/primitives/mac/hmac>`,
in an "encrypt-then-MAC" formulation as `described by Colin Percival`_.
``cryptography`` includes a recipe named :doc:`/fernet` that does this for you.
**To minimize the risk of security issues you should evaluate Fernet to see if
it fits your needs before implementing anything using this module.**

.. class:: Cipher(algorithm, mode, backend)

    Cipher objects combine an algorithm such as
    :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES` with a
    mode like
    :class:`~cryptography.hazmat.primitives.ciphers.modes.CBC` or
    :class:`~cryptography.hazmat.primitives.ciphers.modes.CTR`. A simple
    example of encrypting and then decrypting content with AES is:

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        >>> from cryptography.hazmat.backends import default_backend
        >>> backend = default_backend()
        >>> key = os.urandom(32)
        >>> iv = os.urandom(16)
        >>> cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        >>> encryptor = cipher.encryptor()
        >>> ct = encryptor.update(b"a secret message") + encryptor.finalize()
        >>> decryptor = cipher.decryptor()
        >>> decryptor.update(ct) + decryptor.finalize()
        'a secret message'

    :param algorithms: A
        :class:`~cryptography.hazmat.primitives.ciphers.CipherAlgorithm`
        instance such as those described
        :ref:`below <symmetric-encryption-algorithms>`.
    :param mode: A :class:`~cryptography.hazmat.primitives.ciphers.modes.Mode`
        instance such as those described
        :ref:`below <symmetric-encryption-modes>`.
    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`
        instance.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if the
        provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`

    .. method:: encryptor()

        :return: An encrypting
            :class:`~cryptography.hazmat.primitives.ciphers.CipherContext`
            instance.

        If the backend doesn't support the requested combination of ``cipher``
        and ``mode`` an :class:`~cryptography.exceptions.UnsupportedAlgorithm`
        exception will be raised.

    .. method:: decryptor()

        :return: A decrypting
            :class:`~cryptography.hazmat.primitives.ciphers.CipherContext`
            instance.

        If the backend doesn't support the requested combination of ``cipher``
        and ``mode`` an :class:`~cryptography.exceptions.UnsupportedAlgorithm`
        exception will be raised.

.. _symmetric-encryption-algorithms:

Algorithms
~~~~~~~~~~

.. currentmodule:: cryptography.hazmat.primitives.ciphers.algorithms

.. class:: AES(key)

    AES (Advanced Encryption Standard) is a block cipher standardized by NIST.
    AES is both fast, and cryptographically strong. It is a good default
    choice for encryption.

    :param bytes key: The secret key. This must be kept secret. Either ``128``,
        ``192``, or ``256`` :term:`bits` long.

.. class:: Camellia(key)

    Camellia is a block cipher approved for use by `CRYPTREC`_ and ISO/IEC.
    It is considered to have comparable security and performance to AES but
    is not as widely studied or deployed.

    :param bytes key: The secret key. This must be kept secret. Either ``128``,
        ``192``, or ``256`` :term:`bits` long.

.. class:: ChaCha20(key)

    .. versionadded:: 2.1

    .. note::

        In most cases users should use
        :class:`~cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`
        instead of this class. `ChaCha20` alone does not provide integrity
        so it must be combined with a MAC to be secure.
        :class:`~cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`
        does this for you.

    ChaCha20 is a stream cipher used in several IETF protocols. It is
    standardized in :rfc:`7539`.

    :param bytes key: The secret key. This must be kept secret. ``256``
        :term:`bits` (32 bytes) in length.

    :param bytes nonce: Should be unique, a :term:`nonce`. It is
        critical to never reuse a ``nonce`` with a given key.  Any reuse of a
        nonce with the same key compromises the security of every message
        encrypted with that key. The nonce does not need to be kept secret
        and may be included with the ciphertext. This must be ``128``
        :term:`bits` in length.

        .. note::

            In :rfc:`7539` the nonce is defined as a 96-bit value that is later
            concatenated with a block counter (encoded as a 32-bit
            little-endian). If you have a separate nonce and block counter
            you will need to concatenate it yourself before passing it. For
            example if you have an initial block counter of 2 and a 96-bit
            nonce the concatenated nonce would be
            ``struct.pack("<i", 2) + nonce``.

    .. doctest::

        >>> from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        >>> from cryptography.hazmat.backends import default_backend
        >>> nonce = os.urandom(16)
        >>> algorithm = algorithms.ChaCha20(key, nonce)
        >>> cipher = Cipher(algorithm, mode=None, backend=default_backend())
        >>> encryptor = cipher.encryptor()
        >>> ct = encryptor.update(b"a secret message")
        >>> decryptor = cipher.decryptor()
        >>> decryptor.update(ct)
        'a secret message'

.. class:: TripleDES(key)

    Triple DES (Data Encryption Standard), sometimes referred to as 3DES, is a
    block cipher standardized by NIST. Triple DES has known crypto-analytic
    flaws, however none of them currently enable a practical attack.
    Nonetheless, Triple DES is not recommended for new applications because it
    is incredibly slow; old applications should consider moving away from it.

    :param bytes key: The secret key. This must be kept secret. Either ``64``,
        ``128``, or ``192`` :term:`bits` long. DES only uses ``56``, ``112``,
        or ``168`` bits of the key as there is a parity byte in each component
        of the key.  Some writing refers to there being up to three separate
        keys that are each ``56`` bits long, they can simply be concatenated
        to produce the full key.

.. class:: CAST5(key)

    .. versionadded:: 0.2

    CAST5 (also known as CAST-128) is a block cipher approved for use in the
    Canadian government by the `Communications Security Establishment`_. It is
    a variable key length cipher and supports keys from 40-128 :term:`bits` in
    length.

    :param bytes key: The secret key, This must be kept secret. 40 to 128
        :term:`bits` in length in increments of 8 bits.

.. class:: SEED(key)

    .. versionadded:: 0.4

    SEED is a block cipher developed by the Korea Information Security Agency
    (KISA). It is defined in :rfc:`4269` and is used broadly throughout South
    Korean industry, but rarely found elsewhere.

    :param bytes key: The secret key. This must be kept secret. ``128``
        :term:`bits` in length.

Weak ciphers
------------

.. warning::

    These ciphers are considered weak for a variety of reasons. New
    applications should avoid their use and existing applications should
    strongly consider migrating away.

.. class:: Blowfish(key)

    Blowfish is a block cipher developed by Bruce Schneier. It is known to be
    susceptible to attacks when using weak keys. The author has recommended
    that users of Blowfish move to newer algorithms such as :class:`AES`.

    :param bytes key: The secret key. This must be kept secret. 32 to 448
        :term:`bits` in length in increments of 8 bits.

.. class:: ARC4(key)

    ARC4 (Alleged RC4) is a stream cipher with serious weaknesses in its
    initial stream output. Its use is strongly discouraged. ARC4 does not use
    mode constructions.

    :param bytes key: The secret key. This must be kept secret. Either ``40``,
        ``56``, ``64``, ``80``, ``128``, ``192``, or ``256`` :term:`bits` in
        length.

    .. doctest::

        >>> from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        >>> from cryptography.hazmat.backends import default_backend
        >>> algorithm = algorithms.ARC4(key)
        >>> cipher = Cipher(algorithm, mode=None, backend=default_backend())
        >>> encryptor = cipher.encryptor()
        >>> ct = encryptor.update(b"a secret message")
        >>> decryptor = cipher.decryptor()
        >>> decryptor.update(ct)
        'a secret message'

.. class:: IDEA(key)

    IDEA (`International Data Encryption Algorithm`_) is a block cipher created
    in 1991. It is an optional component of the `OpenPGP`_ standard. This cipher
    is susceptible to attacks when using weak keys. It is recommended that you
    do not use this cipher for new applications.

    :param bytes key: The secret key. This must be kept secret. ``128``
        :term:`bits` in length.


.. _symmetric-encryption-modes:

Modes
~~~~~

.. module:: cryptography.hazmat.primitives.ciphers.modes

.. class:: CBC(initialization_vector)

    CBC (Cipher Block Chaining) is a mode of operation for block ciphers. It is
    considered cryptographically strong.

    **Padding is required when using this mode.**

    :param bytes initialization_vector: Must be :doc:`random bytes
        </random-numbers>`. They do not need to be kept secret and they can be
        included in a transmitted message. Must be the same number of bytes as
        the ``block_size`` of the cipher. Each time something is encrypted a
        new ``initialization_vector`` should be generated. Do not reuse an
        ``initialization_vector`` with a given ``key``, and particularly do not
        use a constant ``initialization_vector``.

    A good construction looks like:

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives.ciphers.modes import CBC
        >>> iv = os.urandom(16)
        >>> mode = CBC(iv)

    While the following is bad and will leak information:

    .. doctest::

        >>> from cryptography.hazmat.primitives.ciphers.modes import CBC
        >>> iv = "a" * 16
        >>> mode = CBC(iv)


.. class:: CTR(nonce)

    .. warning::

        Counter mode is not recommended for use with block ciphers that have a
        block size of less than 128-:term:`bits`.

    CTR (Counter) is a mode of operation for block ciphers. It is considered
    cryptographically strong. It transforms a block cipher into a stream
    cipher.

    **This mode does not require padding.**

    :param bytes nonce: Should be unique, a :term:`nonce`. It is
        critical to never reuse a ``nonce`` with a given key.  Any reuse of a
        nonce with the same key compromises the security of every message
        encrypted with that key. Must be the same number of bytes as the
        ``block_size`` of the cipher with a given key. The nonce does not need
        to be kept secret and may be included with the ciphertext.

.. class:: OFB(initialization_vector)

    OFB (Output Feedback) is a mode of operation for block ciphers. It
    transforms a block cipher into a stream cipher.

    **This mode does not require padding.**

    :param bytes initialization_vector: Must be :doc:`random bytes
        </random-numbers>`. They do not need to be kept secret and they can be
        included in a transmitted message. Must be the same number of bytes as
        the ``block_size`` of the cipher. Do not reuse an
        ``initialization_vector`` with a given ``key``.

.. class:: CFB(initialization_vector)

    CFB (Cipher Feedback) is a mode of operation for block ciphers. It
    transforms a block cipher into a stream cipher.

    **This mode does not require padding.**

    :param bytes initialization_vector: Must be :doc:`random bytes
        </random-numbers>`. They do not need to be kept secret and they can be
        included in a transmitted message. Must be the same number of bytes as
        the ``block_size`` of the cipher. Do not reuse an
        ``initialization_vector`` with a given ``key``.

.. class:: CFB8(initialization_vector)

    CFB (Cipher Feedback) is a mode of operation for block ciphers. It
    transforms a block cipher into a stream cipher. The CFB8 variant uses an
    8-bit shift register.

    **This mode does not require padding.**

    :param bytes initialization_vector: Must be :doc:`random bytes
        </random-numbers>`. They do not need to be kept secret and they can be
        included in a transmitted message. Must be the same number of bytes as
        the ``block_size`` of the cipher. Do not reuse an
        ``initialization_vector`` with a given ``key``.

.. class:: GCM(initialization_vector, tag=None, min_tag_length=16)

    .. danger::

        If you are encrypting data that can fit into memory you should strongly
        consider using
        :class:`~cryptography.hazmat.primitives.ciphers.aead.AESGCM` instead
        of this.

        When using this mode you **must** not use the decrypted data until
        the appropriate finalization method
        (:meth:`~cryptography.hazmat.primitives.ciphers.CipherContext.finalize`
        or
        :meth:`~cryptography.hazmat.primitives.ciphers.AEADDecryptionContext.finalize_with_tag`)
        has been called. GCM provides **no** guarantees of ciphertext integrity
        until decryption is complete.

    GCM (Galois Counter Mode) is a mode of operation for block ciphers. An
    AEAD (authenticated encryption with additional data) mode is a type of
    block cipher mode that simultaneously encrypts the message as well as
    authenticating it. Additional unencrypted data may also be authenticated.
    Additional means of verifying integrity such as
    :doc:`HMAC </hazmat/primitives/mac/hmac>` are not necessary.

    **This mode does not require padding.**

    :param bytes initialization_vector: Must be unique, a :term:`nonce`.
        They do not need to be kept secret and they can be included in a
        transmitted message. NIST `recommends a 96-bit IV length`_ for
        performance critical situations but it can be up to 2\ :sup:`64` - 1
        :term:`bits`. Do not reuse an ``initialization_vector`` with a given
        ``key``.

    .. note::

        Cryptography will generate a 128-bit tag when finalizing encryption.
        You can shorten a tag by truncating it to the desired length but this
        is **not recommended** as it lowers the security margins of the
        authentication (`NIST SP-800-38D`_ recommends 96-:term:`bits` or
        greater).  Applications wishing to allow truncation must pass the
        ``min_tag_length`` parameter.

        .. versionchanged:: 0.5

            The ``min_tag_length`` parameter was added in ``0.5``, previously
            truncation down to ``4`` bytes was always allowed.

    :param bytes tag: The tag bytes to verify during decryption. When
        encrypting this must be ``None``. When decrypting, it may be ``None``
        if the tag is supplied on finalization using
        :meth:`~cryptography.hazmat.primitives.ciphers.AEADDecryptionContext.finalize_with_tag`.
        Otherwise, the tag is mandatory.

    :param bytes min_tag_length: The minimum length ``tag`` must be. By default
        this is ``16``, meaning tag truncation is not allowed. Allowing tag
        truncation is strongly discouraged for most applications.

    :raises ValueError: This is raised if ``len(tag) < min_tag_length``.

    :raises NotImplementedError: This is raised if the version of the OpenSSL
        backend used is 1.0.1 or earlier.

    An example of securely encrypting and decrypting data with ``AES`` in the
    ``GCM`` mode looks like:

    .. testcode::

        import os

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes
        )

        def encrypt(key, plaintext, associated_data):
            # Generate a random 96-bit IV.
            iv = os.urandom(12)

            # Construct an AES-GCM Cipher object with the given key and a
            # randomly generated IV.
            encryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=default_backend()
            ).encryptor()

            # associated_data will be authenticated but not encrypted,
            # it must also be passed in on decryption.
            encryptor.authenticate_additional_data(associated_data)

            # Encrypt the plaintext and get the associated ciphertext.
            # GCM does not require padding.
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            return (iv, ciphertext, encryptor.tag)

        def decrypt(key, associated_data, iv, ciphertext, tag):
            # Construct a Cipher object, with the key, iv, and additionally the
            # GCM tag used for authenticating the message.
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()

            # We put associated_data back in or the tag will fail to verify
            # when we finalize the decryptor.
            decryptor.authenticate_additional_data(associated_data)

            # Decryption gets us the authenticated plaintext.
            # If the tag does not match an InvalidTag exception will be raised.
            return decryptor.update(ciphertext) + decryptor.finalize()

        iv, ciphertext, tag = encrypt(
            key,
            b"a secret message!",
            b"authenticated but not encrypted payload"
        )

        print(decrypt(
            key,
            b"authenticated but not encrypted payload",
            iv,
            ciphertext,
            tag
        ))

    .. testoutput::

        a secret message!

.. class:: XTS(tweak)

    .. versionadded:: 2.1

    .. warning::

        XTS mode is meant for disk encryption and should not be used in other
        contexts. ``cryptography`` only supports XTS mode with
        :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES`.

    .. note::

        AES XTS keys are double length. This means that to do AES-128
        encryption in XTS mode you need a 256-bit key. Similarly, AES-256
        requires passing a 512-bit key. AES 192 is not supported in XTS mode.

    XTS (XEX-based tweaked-codebook mode with ciphertext stealing) is a mode
    of operation for the AES block cipher that is used for `disk encryption`_.

    **This mode does not require padding.**

    :param bytes tweak: The tweak is a 16 byte value typically derived from
        something like the disk sector number. A given ``(tweak, key)`` pair
        should not be reused, although doing so is less catastrophic than
        in CTR mode.


Insecure modes
--------------

.. warning::

    These modes are insecure. New applications should never make use of them,
    and existing applications should strongly consider migrating away.


.. class:: ECB()

    ECB (Electronic Code Book) is the simplest mode of operation for block
    ciphers. Each block of data is encrypted in the same way. This means
    identical plaintext blocks will always result in identical ciphertext
    blocks, which can leave `significant patterns in the output`_.

    **Padding is required when using this mode.**

Interfaces
~~~~~~~~~~

.. currentmodule:: cryptography.hazmat.primitives.ciphers

.. class:: CipherContext

    When calling ``encryptor()`` or ``decryptor()`` on a ``Cipher`` object
    the result will conform to the ``CipherContext`` interface. You can then
    call ``update(data)`` with data until you have fed everything into the
    context. Once that is done call ``finalize()`` to finish the operation and
    obtain the remainder of the data.

    Block ciphers require that the plaintext or ciphertext always be a multiple
    of their block size. Because of that **padding** is sometimes required to
    make a message the correct size. ``CipherContext`` will not automatically
    apply any padding; you'll need to add your own. For block ciphers the
    recommended padding is
    :class:`~cryptography.hazmat.primitives.padding.PKCS7`. If you are using a
    stream cipher mode (such as
    :class:`~cryptography.hazmat.primitives.ciphers.modes.CTR`) you don't have
    to worry about this.

    .. method:: update(data)

        :param bytes data: The data you wish to pass into the context.
        :return bytes: Returns the data that was encrypted or decrypted.
        :raises cryptography.exceptions.AlreadyFinalized: See :meth:`finalize`

        When the ``Cipher`` was constructed in a mode that turns it into a
        stream cipher (e.g.
        :class:`~cryptography.hazmat.primitives.ciphers.modes.CTR`), this will
        return bytes immediately, however in other modes it will return chunks
        whose size is determined by the cipher's block size.

    .. method:: update_into(data, buf)

        .. versionadded:: 1.8

        .. warning::

            This method allows you to avoid a memory copy by passing a writable
            buffer and reading the resulting data. You are responsible for
            correctly sizing the buffer and properly handling the data. This
            method should only be used when extremely high performance is a
            requirement and you will be making many small calls to
            ``update_into``.

        :param bytes data: The data you wish to pass into the context.
        :param buf: A writable Python buffer that the data will be written
            into. This buffer should be ``len(data) + n - 1`` bytes where ``n``
            is the block size (in bytes) of the cipher and mode combination.
        :return int: Number of bytes written.
        :raises NotImplementedError: This is raised if the version of ``cffi``
            used is too old (this can happen on older PyPy releases).
        :raises ValueError: This is raised if the supplied buffer is too small.

        .. doctest::

            >>> import os
            >>> from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            >>> from cryptography.hazmat.backends import default_backend
            >>> backend = default_backend()
            >>> key = os.urandom(32)
            >>> iv = os.urandom(16)
            >>> cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            >>> encryptor = cipher.encryptor()
            >>> # the buffer needs to be at least len(data) + n - 1 where n is cipher/mode block size in bytes
            >>> buf = bytearray(31)
            >>> len_encrypted = encryptor.update_into(b"a secret message", buf)
            >>> # get the ciphertext from the buffer reading only the bytes written to it (len_encrypted)
            >>> ct = bytes(buf[:len_encrypted]) + encryptor.finalize()
            >>> decryptor = cipher.decryptor()
            >>> len_decrypted = decryptor.update_into(ct, buf)
            >>> # get the plaintext from the buffer reading only the bytes written (len_decrypted)
            >>> bytes(buf[:len_decrypted]) + decryptor.finalize()
            'a secret message'

    .. method:: finalize()

        :return bytes: Returns the remainder of the data.
        :raises ValueError: This is raised when the data provided isn't
            a multiple of the algorithm's block size.

        Once ``finalize`` is called this object can no longer be used and
        :meth:`update` and :meth:`finalize` will raise an
        :class:`~cryptography.exceptions.AlreadyFinalized` exception.

.. class:: AEADCipherContext

    When calling ``encryptor`` or ``decryptor`` on a ``Cipher`` object
    with an AEAD mode (e.g.
    :class:`~cryptography.hazmat.primitives.ciphers.modes.GCM`) the result will
    conform to the ``AEADCipherContext`` and ``CipherContext`` interfaces. If
    it is an encryption or decryption context it will additionally be an
    ``AEADEncryptionContext`` or ``AEADDecryptionContext`` instance,
    respectively. ``AEADCipherContext`` contains an additional method
    :meth:`authenticate_additional_data` for adding additional authenticated
    but unencrypted data (see note below). You should call this before calls to
    ``update``. When you are done call ``finalize`` to finish the operation.

    .. note::

        In AEAD modes all data passed to ``update()`` will be both encrypted
        and authenticated. Do not pass encrypted data to the
        ``authenticate_additional_data()`` method. It is meant solely for
        additional data you may want to authenticate but leave unencrypted.

    .. method:: authenticate_additional_data(data)

        :param bytes data: Any data you wish to authenticate but not encrypt.
        :raises: :class:`~cryptography.exceptions.AlreadyFinalized`

.. class:: AEADEncryptionContext

    When creating an encryption context using ``encryptor`` on a ``Cipher``
    object with an AEAD mode such as
    :class:`~cryptography.hazmat.primitives.ciphers.modes.GCM` an object
    conforming to both the ``AEADEncryptionContext`` and ``AEADCipherContext``
    interfaces will be returned.  This interface provides one
    additional attribute ``tag``. ``tag`` can only be obtained after
    ``finalize`` has been called.

    .. attribute:: tag

        :return bytes: Returns the tag value as bytes.
        :raises: :class:`~cryptography.exceptions.NotYetFinalized` if called
            before the context is finalized.

.. class:: AEADDecryptionContext

    .. versionadded:: 1.9

    When creating an encryption context using ``decryptor`` on a ``Cipher``
    object with an AEAD mode such as
    :class:`~cryptography.hazmat.primitives.ciphers.modes.GCM` an object
    conforming to both the ``AEADDecryptionContext`` and ``AEADCipherContext``
    interfaces will be returned.  This interface provides one additional method
    :meth:`finalize_with_tag` that allows passing the authentication tag for
    validation after the ciphertext has been decrypted.

    .. method:: finalize_with_tag(tag)

        .. note::

            This method is not supported when compiled against OpenSSL 1.0.1.

        :param bytes tag: The tag bytes to verify after decryption.
        :return bytes: Returns the remainder of the data.
        :raises ValueError: This is raised when the data provided isn't
            a multiple of the algorithm's block size, if ``min_tag_length`` is
            less than 4, or if ``len(tag) < min_tag_length``.
        :raises NotImplementedError: This is raised if the version of the
            OpenSSL backend used is 1.0.1 or earlier.

        If the authentication tag was not already supplied to the constructor
        of the :class:`~cryptography.hazmat.primitives.ciphers.modes.GCM` mode
        object, this method must be used instead of
        :meth:`~cryptography.hazmat.primitives.ciphers.CipherContext.finalize`.

.. class:: CipherAlgorithm

    A named symmetric encryption algorithm.

    .. attribute:: name

        :type: str

        The standard name for the mode, for example, "AES", "Camellia", or
        "Blowfish".

    .. attribute:: key_size

        :type: int

        The number of :term:`bits` in the key being used.


.. class:: BlockCipherAlgorithm

    A block cipher algorithm.

    .. attribute:: block_size

        :type: int

        The number of :term:`bits` in a block.

Interfaces used by the symmetric cipher modes described in
:ref:`Symmetric Encryption Modes <symmetric-encryption-modes>`.

.. currentmodule:: cryptography.hazmat.primitives.ciphers.modes

.. class:: Mode

    A named cipher mode.

    .. attribute:: name

        :type: str

        This should be the standard shorthand name for the mode, for example
        Cipher-Block Chaining mode is "CBC".

        The name may be used by a backend to influence the operation of a
        cipher in conjunction with the algorithm's name.

    .. method:: validate_for_algorithm(algorithm)

        :param cryptography.hazmat.primitives.ciphers.CipherAlgorithm algorithm:

        Checks that the combination of this mode with the provided algorithm
        meets any necessary invariants. This should raise an exception if they
        are not met.

        For example, the
        :class:`~cryptography.hazmat.primitives.ciphers.modes.CBC` mode uses
        this method to check that the provided initialization vector's length
        matches the block size of the algorithm.


.. class:: ModeWithInitializationVector

    A cipher mode with an initialization vector.

    .. attribute:: initialization_vector

        :type: bytes

        Exact requirements of the initialization are described by the
        documentation of individual modes.


.. class:: ModeWithNonce

    A cipher mode with a nonce.

    .. attribute:: nonce

        :type: bytes

        Exact requirements of the nonce are described by the documentation of
        individual modes.


.. class:: ModeWithAuthenticationTag

    A cipher mode with an authentication tag.

    .. attribute:: tag

        :type: bytes

        Exact requirements of the tag are described by the documentation of
        individual modes.


.. class:: ModeWithTweak

    .. versionadded:: 2.1

    A cipher mode with a tweak.

    .. attribute:: tweak

        :type: bytes

        Exact requirements of the tweak are described by the documentation of
        individual modes.

Exceptions
~~~~~~~~~~

.. currentmodule:: cryptography.exceptions


.. class:: InvalidTag

    This is raised if an authenticated encryption tag fails to verify during
    decryption.



.. _`described by Colin Percival`: http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
.. _`recommends a 96-bit IV length`: https://csrc.nist.gov/publications/detail/sp/800-38d/final
.. _`NIST SP-800-38D`: https://csrc.nist.gov/publications/detail/sp/800-38d/final
.. _`Communications Security Establishment`: https://www.cse-cst.gc.ca
.. _`encrypt`: https://ssd.eff.org/en/module/what-encryption
.. _`CRYPTREC`: https://www.cryptrec.go.jp/english/
.. _`significant patterns in the output`: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29
.. _`International Data Encryption Algorithm`: https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm
.. _`OpenPGP`: http://openpgp.org
.. _`disk encryption`: https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS
