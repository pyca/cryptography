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
        keys. There are seperate encryption and decryption keys.
