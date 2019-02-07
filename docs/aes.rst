aes (symmetric encryption)
=============================

.. currentmodule:: cryptography.aes

aes guarantees that a message encrypted using it cannot be
manipulated or read without the key. aes is an implementation of
symmetric (also known as "secret key") authenticated cryptography.

.. func:: encrypt(key, plaintext, associated_data)

    Encrypts data passed. The result of this encryption has strong
    privacy and authenticity guarantees.

    :param key: The secret key. This must be kept secret. Either ``128``,
                ``192``, or ``256`` :term:`bits` long.
    :type key: :term:`bytes-like`
    :param bytes plaintext: The message you would like to encrypt.
    :param bytes associated_data: Data that will be authenticated but not
                                  encrypted, it must also be passed in on
                                  decryption.
    :returns tuple: tuple containing:
        bytes: the iv
        bytes: A secure message that cannot be read or altered without the key.
        bytes: An authentication tag, must also be passed to decrypt.

.. func:: decrypt(key, associated_data, iv, ciphertext, tag)
    Decrypts data passed. If successfully decrypted you will receive the
    original plaintext as the result, otherwise an exception will be
    raised. It is safe to use this data immediately as this function
    verifies that the data has not been tampered with prior to returning it.

    :param key: The secret key. This must be kept secret. Either ``128``,
                ``192``, or ``256`` :term:`bits` long.
    :type key: :term:`bytes-like`
    :param bytes associated_data: Plaintext data that will be authenticated but
                                  not decrypted.
    :param bytes iv: The initialization vector, returned from encrypt.
    :param bytes ciphertext: The data you would like to decrypt, returned from
                             encrypt.
    :param bytes tag: The authentication tag, returned from encrypt.

Implementation
--------------

This module is built on top of a number of standard cryptographic primitives.
Specifically it uses:

* :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES` in
  :class:`~cryptography.hazmat.primitives.ciphers.modes.GCM` mode.
* Initialization vectors are generated using ``os.urandom()``.

For complete details consult the `specification`_.

Limitations
-----------

These functions are ideal for encrypting data that easily fits in memory. As a design
feature it does not expose unauthenticated bytes. Unfortunately, this makes it
generally unsuitable for very large files at this time.
