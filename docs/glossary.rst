Glossary
========

.. glossary::
    :sorted:

    plaintext
        User-readable data you care about.

    ciphertext
        The encoded data, it's not user readable. Potential attackers are able
        to see this.

    encryption
        The process of converting plaintext to ciphertext.

    decryption
        The process of converting ciphertext to plaintext.

    key
        Secret data is encoded with a function using this key. Sometimes
        multiple keys are used. These **must** be kept secret, if a key is
        exposed to an attacker, any data encrypted with it will be exposed.

    symmetric cryptography
        Cryptographic operations where encryption and decryption use the same
        key.

    public-key cryptography
    asymmetric cryptography
        Cryptographic operations where encryption and decryption use different
        keys. There are separate encryption and decryption keys. Typically
        encryption is performed using a :term:`public key`, and it can then be
        decrypted using a :term:`private key`. Asymmetric cryptography can also
        be used to create signatures, which can be generated with a
        :term:`private key` and verified with a :term:`public key`.

    public key
        This is one of two keys involved in :term:`public-key cryptography`. It
        can be used to encrypt messages for someone possessing the
        corresponding :term:`private key` and to verify signatures created with
        the corresponding :term:`private key`. This can be distributed
        publicly, hence the name.

    private key
        This is one of two keys involved in :term:`public-key cryptography`. It
        can be used to decrypt messages which were encrypted with the
        corresponding :term:`public key`, as well as to create signatures,
        which can be verified with the corresponding :term:`public key`. These
        **must** be kept secret, if they are exposed, all encrypted messages
        are compromised, and an attacker will be able to forge signatures.

    authentication
        The process of verifying that a message was created by a specific
        individual (or program). Like encryption, authentication can be either
        symmetric or asymmetric. Authentication is necessary for effective
        encryption.

    ciphertext indistinguishability
        This is a property of encryption systems whereby two encrypted messages
        aren't distinguishable without knowing the encryption key. This is
        considered a basic, necessary property for a working encryption system.

    text
        This type corresponds to ``unicode`` on Python 2 and ``str`` on Python
        3.  This is equivalent to ``six.text_type``.

    nonce
        A nonce is a **n**\ umber used **once**. Nonces are used in many
        cryptographic protocols. Generally, a nonce does not have to be secret
        or unpredictable, but it must be unique. A nonce is often a random
        or pseudo-random number (see :doc:`Random number generation
        </random-numbers>`). Since a nonce does not have to be unpredictable,
        it can also take a form of a counter.

    opaque key
        An opaque key is a type of key that allows you to perform cryptographic
        operations such as encryption, decryption, signing, and verification,
        but does not allow access to the key itself. Typically an opaque key is
        loaded from a `hardware security module`_ (HSM).

    A-label
        The ASCII compatible encoded (ACE) representation of an
        internationalized (unicode) domain name. A-labels begin with the
        prefix ``xn--``. To create an A-label from a unicode domain string use
        a library like `idna`_.

    bits
        A bit is binary value -- a value that has only two possible states.
        Typically binary values are represented visually as 0 or 1, but
        remember that their actual value is not a printable character. A byte
        on modern computers is 8 bits and represents 256 possible values. In
        cryptographic applications when you see something say it requires a 128
        bit key, you can calculate the number of bytes by dividing by 8. 128
        divided by 8 is 16, so a 128 bit key is a 16 byte key.

    bytes-like
        A bytes-like object contains binary data and supports the
        `buffer protocol`_. This includes ``bytes``, ``bytearray``, and
        ``memoryview`` objects.

    U-label
        The presentational unicode form of an internationalized domain
        name. U-labels use unicode characters outside the ASCII range and
        are encoded as A-labels when stored in certificates.

.. _`hardware security module`: https://en.wikipedia.org/wiki/Hardware_security_module
.. _`idna`: https://pypi.org/project/idna/
.. _`buffer protocol`: https://docs.python.org/3/c-api/buffer.html
