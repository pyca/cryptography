.. hazmat::


Symmetric Encryption
====================

.. currentmodule:: cryptography.hazmat.primitives.ciphers

.. testsetup::

    import binascii
    key = binascii.unhexlify(b"0" * 32)
    iv = binascii.unhexlify(b"0" * 32)


Symmetric encryption is a way to encrypt (hide the plaintext value) material
where the sender and receiver both use the same key. Note that symmetric
encryption is **not** sufficient for most applications, because it only
provides secrecy (an attacker can't see the message) but not authenticity (an
attacker can create bogus messages and force the application to decrypt them).
For this reason it is *strongly* recommended to combine encryption with a
message authentication code, such as :doc:`HMAC </hazmat/primitives/hmac>`, in
an "encrypt-then-MAC" formulation as `described by Colin Percival`_.

.. class:: Cipher(algorithm, mode, backend)

    Cipher objects combine an algorithm (such as
    :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES`) with a
    mode (such as
    :class:`~cryptography.hazmat.primitives.ciphers.modes.CBC` or
    :class:`~cryptography.hazmat.primitives.ciphers.modes.CTR`). A simple
    example of encrypting (and then decrypting) content with AES is:

    .. doctest::

        >>> from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        >>> from cryptography.hazmat.backends import default_backend
        >>> backend = default_backend()
        >>> cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        >>> encryptor = cipher.encryptor()
        >>> ct = encryptor.update(b"a secret message") + encryptor.finalize()
        >>> decryptor = cipher.decryptor()
        >>> decryptor.update(ct) + decryptor.finalize()
        'a secret message'

    :param algorithms: A
        :class:`~cryptography.hazmat.primitives.interfaces.CipherAlgorithm`
        provider such as those described
        :ref:`below <symmetric-encryption-algorithms>`.
    :param mode: A :class:`~cryptography.hazmat.primitives.interfaces.Mode`
        provider such as those described
        :ref:`below <symmetric-encryption-modes>`.
    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`
        provider.

    .. method:: encryptor()

        :return: An encrypting
            :class:`~cryptography.hazmat.primitives.interfaces.CipherContext`
            provider.

        If the backend doesn't support the requested combination of ``cipher``
        and ``mode`` an :class:`~cryptography.exceptions.UnsupportedAlgorithm`
        will be raised.

    .. method:: decryptor()

        :return: A decrypting
            :class:`~cryptography.hazmat.primitives.interfaces.CipherContext`
            provider.

        If the backend doesn't support the requested combination of ``cipher``
        and ``mode`` an :class:`cryptography.exceptions.UnsupportedAlgorithm`
        will be raised.


.. currentmodule:: cryptography.hazmat.primitives.interfaces

.. class:: CipherContext

    When calling ``encryptor()`` or ``decryptor()`` on a ``Cipher`` object
    you will receive a return object conforming to the ``CipherContext``
    interface. You can then call ``update(data)`` with data until you have fed
    everything into the context. Once that is done call ``finalize()`` to
    finish the operation and obtain the remainder of the data.

    Block ciphers require that plaintext or ciphertext always be a multiple of
    their block size, because of that **padding** is often required to make a
    message the correct size. ``CipherContext`` will not automatically apply
    any padding; you'll need to add your own. For block ciphers the recommended
    padding is :class:`cryptography.hazmat.primitives.padding.PKCS7`. If you
    are using a stream cipher mode (such as
    :class:`cryptography.hazmat.primitives.modes.CTR`) you don't have to worry
    about this.

    .. method:: update(data)

        :param bytes data: The data you wish to pass into the context.
        :return bytes: Returns the data that was encrypted or decrypted.
        :raises cryptography.exceptions.AlreadyFinalized: See :meth:`finalize`

        When the ``Cipher`` was constructed in a mode that turns it into a
        stream cipher (e.g.
        :class:`cryptography.hazmat.primitives.ciphers.modes.CTR`), this will
        return bytes immediately, however in other modes it will return chunks,
        whose size is determined by the cipher's block size.

    .. method:: finalize()

        :return bytes: Returns the remainder of the data.
        :raises ValueError: This is raised when the data provided isn't
                            correctly padded to be a multiple of the
                            algorithm's block size.

        Once ``finalize`` is called this object can no longer be used and
        :meth:`update` and :meth:`finalize` will raise
        :class:`~cryptography.exceptions.AlreadyFinalized`.

.. class:: AEADCipherContext

    When calling ``encryptor()`` or ``decryptor()`` on a ``Cipher`` object
    with an AEAD mode you will receive a return object conforming to the
    ``AEADCipherContext`` interface (in addition to the ``CipherContext``
    interface). If it is an encryption context it will additionally be an
    ``AEADEncryptionContext`` interface. ``AEADCipherContext`` contains an
    additional method ``authenticate_additional_data`` for adding additional
    authenticated but unencrypted data. You should call this before calls to
    ``update``. When you are done call ``finalize()`` to finish the operation.

    .. method:: authenticate_additional_data(data)

        :param bytes data: The data you wish to authenticate but not encrypt.
        :raises: :class:`~cryptography.exceptions.AlreadyFinalized`

.. class:: AEADEncryptionContext

    When creating an encryption context using ``encryptor()`` on a ``Cipher``
    object with an AEAD mode you will receive a return object conforming to the
    ``AEADEncryptionContext`` interface (as well as ``AEADCipherContext``).
    This interface provides one additional attribute ``tag``. ``tag`` can only
    be obtained after ``finalize()``.

    .. attribute:: tag

        :return bytes: Returns the tag value as bytes.
        :raises: :class:`~cryptography.exceptions.NotYetFinalized` if called
                 before the context is finalized.

.. _symmetric-encryption-algorithms:

Algorithms
~~~~~~~~~~

.. currentmodule:: cryptography.hazmat.primitives.ciphers.algorithms

.. class:: AES(key)

    AES (Advanced Encryption Standard) is a block cipher standardized by NIST.
    AES is both fast, and cryptographically strong. It is a good default
    choice for encryption.

    :param bytes key: The secret key, either ``128``, ``192``, or ``256`` bits.
                      This must be kept secret.

.. class:: Camellia(key)

    Camellia is a block cipher approved for use by CRYPTREC and ISO/IEC.
    It is considered to have comparable security and performance to AES, but
    is not as widely studied or deployed.

    :param bytes key: The secret key, either ``128``, ``192``, or ``256`` bits.
                      This must be kept secret.


.. class:: TripleDES(key)

    Triple DES (Data Encryption Standard), sometimes referred to as 3DES, is a
    block cipher standardized by NIST. Triple DES has known crypto-analytic
    flaws, however none of them currently enable a practical attack.
    Nonetheless, Triples DES is not recommended for new applications because it
    is incredibly slow; old applications should consider moving away from it.

    :param bytes key: The secret key, either ``64``, ``128``, or ``192`` bits
                      (note that DES functionally uses ``56``, ``112``, or
                      ``168`` bits of the key, there is a parity byte in each
                      component of the key), in some materials these are
                      referred to as being up to three separate keys (each
                      ``56`` bits long), they can simply be concatenated to
                      produce the full key. This must be kept secret.

.. class:: CAST5(key)

    CAST5 (also known as CAST-128) is a block cipher approved for use in the
    Canadian government by their Communications Security Establishment. It is a
    variable key length cipher and supports keys from 40-128 bits in length.

    :param bytes key: The secret key, 40-128 bits in length (in increments of
                      8).  This must be kept secret.

Weak Ciphers
------------

.. warning::

    These ciphers are considered weak for a variety of reasons. New
    applications should avoid their use and existing applications should
    strongly consider migrating away.

.. class:: Blowfish(key)

    Blowfish is a block cipher developed by Bruce Schneier. It is known to be
    susceptible to attacks when using weak keys. The author has recommended
    that users of Blowfish move to newer algorithms, such as :class:`AES`.

    :param bytes key: The secret key, 32-448 bits in length (in increments of
                      8).  This must be kept secret.

.. class:: ARC4(key)

    ARC4 (Alleged RC4) is a stream cipher with serious weaknesses in its
    initial stream output. Its use is strongly discouraged. ARC4 does not use
    mode constructions.

    :param bytes key: The secret key, ``40``, ``56``, ``64``, ``80``, ``128``,
                      ``192``, or ``256`` bits in length.  This must be kept
                      secret.

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


.. _symmetric-encryption-modes:

Modes
~~~~~

.. currentmodule:: cryptography.hazmat.primitives.ciphers.modes

.. class:: CBC(initialization_vector)

    CBC (Cipher block chaining) is a mode of operation for block ciphers. It is
    considered cryptographically strong.

    :param bytes initialization_vector: Must be random bytes. They do not need
                                        to be kept secret (they can be included
                                        in a transmitted message). Must be the
                                        same number of bytes as the
                                        ``block_size`` of the cipher. Each time
                                        something is encrypted a new
                                        ``initialization_vector`` should be
                                        generated. Do not reuse an
                                        ``initialization_vector`` with
                                        a given ``key``, and particularly do
                                        not use a constant
                                        ``initialization_vector``.

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
        block size of less than 128-bits.

    CTR (Counter) is a mode of operation for block ciphers. It is considered
    cryptographically strong. It transforms a block cipher into a stream
    cipher.

    :param bytes nonce: Should be random bytes. It is critical to never reuse a
                        ``nonce`` with a given key.  Any reuse of a nonce
                        with the same key compromises the security of every
                        message encrypted with that key. Must be the same
                        number of bytes as the ``block_size`` of the cipher
                        with a given key. The nonce does not need to be kept
                        secret and may be included alongside the ciphertext.

.. class:: OFB(initialization_vector)

    OFB (Output Feedback) is a mode of operation for block ciphers. It
    transforms a block cipher into a stream cipher.

    :param bytes initialization_vector: Must be random bytes. They do not need
                                        to be kept secret (they can be included
                                        in a transmitted message). Must be the
                                        same number of bytes as the
                                        ``block_size`` of the cipher. Do not
                                        reuse an ``initialization_vector`` with
                                        a given ``key``.

.. class:: CFB(initialization_vector)

    CFB (Cipher Feedback) is a mode of operation for block ciphers. It
    transforms a block cipher into a stream cipher.

    :param bytes initialization_vector: Must be random bytes. They do not need
                                        to be kept secret (they can be included
                                        in a transmitted message). Must be the
                                        same number of bytes as the
                                        ``block_size`` of the cipher. Do not
                                        reuse an ``initialization_vector`` with
                                        a given ``key``.

.. class:: GCM(initialization_vector, tag=None)

    .. danger::

        When using this mode you MUST not use the decrypted data until
        :meth:`~cryptography.hazmat.primitives.interfaces.CipherContext.finalize`
        has been called. GCM provides NO guarantees of ciphertext integrity
        until decryption is complete.

    GCM (Galois Counter Mode) is a mode of operation for block ciphers. An
    AEAD (authenticated encryption with additional data) mode is a type of
    block cipher mode that encrypts the message as well as authenticating it
    (and optionally additional data that is not encrypted) simultaneously.
    Additional means of verifying integrity (like
    :doc:`HMAC </hazmat/primitives/hmac>`) are not necessary.

    :param bytes initialization_vector: Must be random bytes. They do not need
                                        to be kept secret (they can be included
                                        in a transmitted message). NIST
                                        `recommends 96-bit IV length`_ for
                                        performance critical situations, but it
                                        can be up to 2\ :sup:`64` - 1 bits.
                                        Do not reuse an ``initialization_vector``
                                        with a given ``key``.

    :param bytes tag: The tag bytes to verify during decryption. When encrypting
                      this must be None.

    .. doctest::

        >>> from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        >>> from cryptography.hazmat.backends import default_backend
        >>> cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        >>> encryptor = cipher.encryptor()
        >>> encryptor.authenticate_additional_data(b"authenticated but not encrypted payload")
        >>> ct = encryptor.update(b"a secret message") + encryptor.finalize()
        >>> tag = encryptor.tag
        >>> cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend)
        >>> decryptor = cipher.decryptor()
        >>> decryptor.authenticate_additional_data(b"authenticated but not encrypted payload")
        >>> decryptor.update(ct) + decryptor.finalize()
        'a secret message'


Insecure Modes
--------------

.. warning::

    These modes are insecure. New applications should never make use of them,
    and existing applications should strongly consider migrating away.


.. class:: ECB()

    ECB (Electronic Code Book) is the simplest mode of operation for block
    ciphers. Each block of data is encrypted in the same way. This means
    identical plaintext blocks will always result in identical ciphertext
    blocks, and thus result in information leakage


.. _`described by Colin Percival`: http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
.. _`recommends 96-bit IV length`: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
