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
        This type corresponds to `unicode` on Python 2 and `str` on Python 3.
        This is equivalent to `six.text_type`.
