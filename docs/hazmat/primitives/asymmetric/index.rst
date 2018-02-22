.. hazmat::

Asymmetric algorithms
=====================

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

Encryption with asymmetric cryptography works in a slightly different way from
symmetric encryption. Someone with the public key is able to encrypt a message,
providing confidentiality, and then only the person in possession of the
private key is able to decrypt it.

.. toctree::
    :maxdepth: 1

    x25519
    ec
    rsa
    dh
    dsa
    serialization
    utils


.. _`proof of identity`: https://en.wikipedia.org/wiki/Public-key_infrastructure
