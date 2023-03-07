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

    ed25519
    x25519
    ed448
    x448
    ec
    rsa
    dh
    dsa
    serialization
    utils


.. _`proof of identity`: https://en.wikipedia.org/wiki/Public-key_infrastructure

Common types
~~~~~~~~~~~~

Asymmetric key types do not inherit from a common base class. The following
union type aliases can be used instead to reference a multitude of key types.

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.types

.. data:: PublicKeyTypes

    .. versionadded:: 40.0.0

    Type alias: A union of all public key types supported:
    :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.x448.X448PublicKey`.

.. data:: PrivateKeyTypes

    .. versionadded:: 40.0.0

    Type alias: A union of all private key types supported:
    :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey`.

.. data:: CertificatePublicKeyTypes

    .. versionadded:: 40.0.0

    Type alias: A union of all public key types supported for X.509
    certificates:
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.x448.X448PublicKey`.

.. data:: CertificateIssuerPublicKeyTypes

    .. versionadded:: 40.0.0

    Type alias: A union of all public key types that can sign other X.509
    certificates as an issuer. x448/x25519 can be a public key, but cannot be
    used in signing, so they are not allowed in these contexts.

    Allowed:
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey`.

.. data:: CertificateIssuerPrivateKeyTypes

    .. versionadded:: 40.0.0

    Type alias: A union of all private key types that can sign other X.509
    certificates as an issuer. x448/x25519 can be a public key, but cannot be
    used in signing, so they are not allowed in these contexts.

    Allowed:
    :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`,
    :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey`.
