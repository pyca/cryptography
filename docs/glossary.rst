Glossary
========

.. glossary::

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

    asymmetric cryptography
        Cryptographic operations where encryption and decryption use different
        keys. There are separate encryption and decryption keys.

    authentication
        The process of verifying that a message was created by a specific
        individual (or program). Like encryption, authentication can be either
        symmetric or asymmetric. Authentication is necessary for effective
        encryption.

    Ciphertext indistinguishability
        This is a property of encryption systems whereby two encrypted messages
        aren't distinguishable without knowing the encryption key. This is
        considered a basic, necessary property for a working encryption system.
