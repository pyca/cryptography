Introduction to Asymmetric Cryptography
=======================================

Asymmetric cryptography is a branch of cryptography where a secret key can be
divided into two parts, a :term:`public key` and a :term:`private key`. The
public key can be given to anyone, trusted or not, while the private key must
be kept secret (just like the key in symmetric cryptography).

Asymmetric cryptography has two primary use cases: authentication and
confidentiality. Using asymmetric cryptography, messages can be signed with a
private key, and then anyone with the public key is able to verify that the
message was created by someone possessing the corresponding private key. This
can be combined with a `proof of identity`_ system to know what entity (person
or group) actually owns that private key, providing authentication.

Encryption with asymmetric cryptography works in a slightly different way.
Someone with the public key is able to encrypt a message, providing
confidentiality, and then only the person in possession of the private key is
able to decrypt it.

This tutorial will walk you through using ``cryptography`` for both of these
use cases. All of the examples will use `RSA`_, the most widely used asymmetric
cryptographic system, which is used in protocols such as TLS and PGP.

Key Generation
--------------

Unlike symmetric cryptography, where the key is typically just a random series
of bytes, RSA keys have a complex internal structure with `specific
mathematical properties`_. Each asymmetric algorithm has an API for generating
new private keys:

.. doctest::

    >>> from cryptography.hazmat.backends import default_backend
    >>> from cryptography.hazmat.primitives.asymmetric import rsa
    >>> private_key = rsa.generate_private_key(
    ...     key_size=2048,
    ...     public_exponent=65537,
    ...     backend=default_backend()
    ... )

This creates a new private key (and its derived public key). ``key_size``
describes how many bits long the key should be, larger keys provide more
security, currently ``1024`` and below are considered breakable, and ``2048``
or ``4096`` are reasonable default key sizes for new keys. The
``public_exponent`` indicates what one mathematical property of the key
generation will be, ``65537`` should almost always be used.

Once you have a private key, you can obtain the corresponding public key:

.. doctest::

    >>> public_key = private_key.public_key()

Key serialization
-----------------

Because RSA keys are more complex than just a series of random bytes, there are
specific serialization formats which are usually used to represent keys on disk
or over a network:

.. doctest::

    >>> # ...

Key loading
-----------

If you already have an on-disk key, which you would like to load for use within
``cryptography``, there are APIs for loading keys in many different formats.
Here is an example of loading an RSA key in the popular PKCS #8 format:

.. code-block:: pycon

    >>> from cryptography.hazmat.backends import default_backend
    >>> from cryptography.hazmat.primitives import serialization
    >>> with open("path/to/key.pem", "rb") as key_file:
    ...     private_key = serialization.load_pem_pkcs8_private_key(
    ...         key_file.read(),
    ...         password=None,
    ...         backend=default_backend()
    ...     )

PKCS #8 optionally supports encrypting keys on disk using a password. In this
example we loaded an unencrypted key, and there we did not provide a password.

Signing
-------

A private key can be used to sign a message. This allows anyone with the public
key to verify that the message was created by someone who possesses the
corresponding private key. RSA signatures require a specific hash function, and
mode to be used. Here is an example of signing ``message`` using RSA, with a
secure hash function and mode:

.. doctest::

    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.primitives.asymmetric import padding
    >>> signer = private_key.signer(
    ...     padding.PSS(
    ...         mgf=padding.MGF1(hashes.SHA256()),
    ...         salt_length=padding.PSS.MAX_LENGTH
    ...     ),
    ...     hashes.SHA256()
    ... )
    >>> message = b"A message I want to sign"
    >>> signer.update(message)
    >>> signature = signer.finalize()
    >>> signature
    '...'

.. more words go here about wtf all that means

Signature Verification
----------------------

The previous section describes what to do if you have a private key and want to
sign something. If you have a public key, a message, and a signature, you can
check that the public key genuinely was used to sign that specific message. You
also need to know which signing algorithm was used, usually these are
prearranged for a given protocol, though it's also possible to include this
metadata with the message:

.. doctest::

    >>> verifier = public_key.verifier(
    ...     signature,
    ...     padding.PSS(
    ...         mgf=padding.MGF1(hashes.SHA256()),
    ...         salt_length=padding.PSS.MAX_LENGTH
    ...     ),
    ...     hashes.SHA256()
    ... )
    >>> verifier.update(message)
    >>> verifier.verify()

If the signature does not match, ``verify()`` will raise an
:class:`~cryptography.exceptions.InvalidSignature` exception.

Encrypt
-------

As stated earlier, asymmetric encryption has the interesting property that you
can encrypt a message without knowing any secrets, encryption requires only the
public key. Once a message is encrypted though, only someone with the private
key is able to decrypt it, even the person who just encrypted the message isn't
able to!

This property means that you can distribute a public key, and then anyone is
able to send you an encrypted message. Like signatures, RSA encryption requires
a specific mode and padding to use.

.. doctest::

    >>> message = b"Something I want to encrypt"
    >>> ciphertext = public_key.encrypt(
    ...     message,
    ...     padding.OAEP(
    ...         mgf=padding.MGF1(hashes.SHA1()),
    ...         algorithm=hashes.SHA256(),
    ...         label=None
    ...     )
    ... )
    >>> ciphertext
    '...'

.. more words about some of this nonsense, what even /is/ an MGF

RSA encryption also has the property that you cannot encrypt a message which is
longer than the ``key_size`` of your key. As a result, RSA is often combined
with symmetric encryption to create a `hybrid cryptosystem`, utilizing both
asymmetric and symmetric algorithms. An example of such a system is PGP.

In protocols where both parties have a PGP key, encryption is typically used
alongside signatures. For example, if I wanted to send you a message, I would
encrypt a message for your public key, and then sign that encrypted blob using
my private key. That way you're able to both read the message, and verify that
it was sent by me.

Decryption
----------

Finally, if we have an encrypted message, we can decrypt it using our private
key. Like signatures, we need to know the mode and algorithm that a message was
encrypted with:

.. doctest::

    >>> plaintext = private_key.decrypt(
    ...     ciphertext,
    ...     padding.OAEP(
    ...         mgf=padding.MGF1(hashes.SHA1()),
    ...         algorithm=hashes.SHA256(),
    ...         label=None
    ...     )
    ... )
    >>> plaintext == message
    True


.. _`proof of identity`: https://en.wikipedia.org/wiki/Public-key_infrastructure
.. _`RSA`: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
.. _`specific mathematical properties`: https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
