Tutorial
========

X.509 certificates are used to authenticate clients and servers. The most
common use case is for web servers using HTTPS.

Creating a Certificate Signing Request (CSR)
--------------------------------------------

When obtaining a certificate from a certificate authority (CA), the usual
flow is:

1. You generate a private/public key pair.
2. You create a request for a certificate, which is signed by your key (to
   prove that you own that key).
3. You give your CSR to a CA (but *not* the private key).
4. The CA validates that you own the resource (e.g. domain) you want a
   certificate for.
5. The CA gives you a certificate, signed by them, which identifies your public
   key, and the resource you are authenticated for.
6. You configure your server to use that certificate, combined with your
   private key, to server traffic.

If you want to obtain a certificate from a typical commercial CA, here's how.
First, you'll need to generate a private key, we'll generate an RSA key (these
are the most common types of keys on the web right now):

.. code-block:: pycon

    >>> from cryptography.hazmat.primitives import serialization
    >>> from cryptography.hazmat.primitives.asymmetric import rsa
    >>> # Generate our key
    >>> key = rsa.generate_private_key(
    ...     public_exponent=65537,
    ...     key_size=2048,
    ... )
    >>> # Write our key to disk for safe keeping
    >>> with open("path/to/store/key.pem", "wb") as f:
    ...     f.write(key.private_bytes(
    ...         encoding=serialization.Encoding.PEM,
    ...         format=serialization.PrivateFormat.TraditionalOpenSSL,
    ...         encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ...     ))

If you've already generated a key you can load it with
:func:`~cryptography.hazmat.primitives.serialization.load_pem_private_key`.

Next we need to generate a certificate signing request. A typical CSR contains
a few details:

* Information about our public key (including a signature of the entire body).
* Information about who *we* are.
* Information about what domains this certificate is for.

.. code-block:: pycon

    >>> from cryptography import x509
    >>> from cryptography.x509.oid import NameOID
    >>> from cryptography.hazmat.primitives import hashes
    >>> # Generate a CSR
    >>> csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    ...     # Provide various details about who we are.
    ...     x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ...     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    ...     x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    ...     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
    ...     x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
    ... ])).add_extension(
    ...     x509.SubjectAlternativeName([
    ...         # Describe what sites we want this certificate for.
    ...         x509.DNSName("mysite.com"),
    ...         x509.DNSName("www.mysite.com"),
    ...         x509.DNSName("subdomain.mysite.com"),
    ...     ]),
    ...     critical=False,
    ... # Sign the CSR with our private key.
    ... ).sign(key, hashes.SHA256())
    >>> # Write our CSR out to disk.
    >>> with open("path/to/csr.pem", "wb") as f:
    ...     f.write(csr.public_bytes(serialization.Encoding.PEM))

Now we can give our CSR to a CA, who will give a certificate to us in return.

Creating a self-signed certificate
----------------------------------

While most of the time you want a certificate that has been *signed* by someone
else (i.e. a certificate authority), so that trust is established, sometimes
you want to create a self-signed certificate. Self-signed certificates are not
issued by a certificate authority, but instead they are signed by the private
key corresponding to the public key they embed.

This means that other people don't trust these certificates, but it also means
they can be issued very easily. In general the only use case for a self-signed
certificate is local testing, where you don't need anyone else to trust your
certificate.

Like generating a CSR, we start with creating a new private key:

.. code-block:: pycon

    >>> # Generate our key
    >>> key = rsa.generate_private_key(
    ...     public_exponent=65537,
    ...     key_size=2048,
    ... )
    >>> # Write our key to disk for safe keeping
    >>> with open("path/to/store/key.pem", "wb") as f:
    ...     f.write(key.private_bytes(
    ...         encoding=serialization.Encoding.PEM,
    ...         format=serialization.PrivateFormat.TraditionalOpenSSL,
    ...         encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ...     ))

Then we generate the certificate itself:

.. code-block:: pycon

    >>> # Various details about who we are. For a self-signed certificate the
    >>> # subject and issuer are always the same.
    >>> subject = issuer = x509.Name([
    ...     x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ...     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    ...     x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    ...     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
    ...     x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
    ... ])
    >>> cert = x509.CertificateBuilder().subject_name(
    ...     subject
    ... ).issuer_name(
    ...     issuer
    ... ).public_key(
    ...     key.public_key()
    ... ).serial_number(
    ...     x509.random_serial_number()
    ... ).not_valid_before(
    ...     datetime.datetime.now(datetime.timezone.utc)
    ... ).not_valid_after(
    ...     # Our certificate will be valid for 10 days
    ...     datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ... ).add_extension(
    ...     x509.SubjectAlternativeName([x509.DNSName("localhost")]),
    ...     critical=False,
    ... # Sign our certificate with our private key
    ... ).sign(key, hashes.SHA256())
    >>> # Write our certificate out to disk.
    >>> with open("path/to/certificate.pem", "wb") as f:
    ...     f.write(cert.public_bytes(serialization.Encoding.PEM))

And now we have a private key and certificate that can be used for local
testing.

Creating a CA hierarchy
-----------------------

When building your own root hierarchy you need to generate a CA and then
issue certificates (typically intermediates) using it. This example shows
how to generate a root CA, a signing intermediate, and issues a leaf
certificate off that intermediate. X.509 is a complex specification so
this example will require adaptation (typically different extensions)
for specific operating environments.

Note that this example does not add CRL distribution point or OCSP AIA
extensions, nor does it save the key/certs to persistent storage.

.. doctest::

    >>> import datetime
    >>> from cryptography.hazmat.primitives.asymmetric import ec
    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.x509.oid import NameOID
    >>> from cryptography import x509
    >>> # Generate our key
    >>> root_key = ec.generate_private_key(ec.SECP256R1())
    >>> subject = issuer = x509.Name([
    ...     x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ...     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    ...     x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    ...     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
    ...     x509.NameAttribute(NameOID.COMMON_NAME, "PyCA Docs Root CA"),
    ... ])
    >>> root_cert = x509.CertificateBuilder().subject_name(
    ...     subject
    ... ).issuer_name(
    ...     issuer
    ... ).public_key(
    ...     root_key.public_key()
    ... ).serial_number(
    ...     x509.random_serial_number()
    ... ).not_valid_before(
    ...     datetime.datetime.now(datetime.timezone.utc)
    ... ).not_valid_after(
    ...     # Our certificate will be valid for ~10 years
    ...     datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*10)
    ... ).add_extension(
    ...     x509.BasicConstraints(ca=True, path_length=None),
    ...     critical=True,
    ... ).add_extension(
    ...     x509.KeyUsage(
    ...         digital_signature=True,
    ...         content_commitment=False,
    ...         key_encipherment=False,
    ...         data_encipherment=False,
    ...         key_agreement=False,
    ...         key_cert_sign=True,
    ...         crl_sign=True,
    ...         encipher_only=False,
    ...         decipher_only=False,
    ...     ),
    ...     critical=True,
    ... ).add_extension(
    ...     x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
    ...     critical=False,
    ... ).sign(root_key, hashes.SHA256())

With a root certificate created we now want to create our intermediate.

.. doctest::

    >>> # Generate our intermediate key
    >>> int_key = ec.generate_private_key(ec.SECP256R1())
    >>> subject = x509.Name([
    ...     x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ...     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    ...     x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    ...     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
    ...     x509.NameAttribute(NameOID.COMMON_NAME, "PyCA Docs Intermediate CA"),
    ... ])
    >>> int_cert = x509.CertificateBuilder().subject_name(
    ...     subject
    ... ).issuer_name(
    ...     root_cert.subject
    ... ).public_key(
    ...     int_key.public_key()
    ... ).serial_number(
    ...     x509.random_serial_number()
    ... ).not_valid_before(
    ...     datetime.datetime.now(datetime.timezone.utc)
    ... ).not_valid_after(
    ...     # Our intermediate will be valid for ~3 years
    ...     datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*3)
    ... ).add_extension(
    ...     # Allow no further intermediates (path length 0)
    ...     x509.BasicConstraints(ca=True, path_length=0),
    ...     critical=True,
    ... ).add_extension(
    ...     x509.KeyUsage(
    ...         digital_signature=True,
    ...         content_commitment=False,
    ...         key_encipherment=False,
    ...         data_encipherment=False,
    ...         key_agreement=False,
    ...         key_cert_sign=True,
    ...         crl_sign=True,
    ...         encipher_only=False,
    ...         decipher_only=False,
    ...     ),
    ...     critical=True,
    ... ).add_extension(
    ...     x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()),
    ...     critical=False,
    ... ).add_extension(
    ...     x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
    ...         root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    ...     ),
    ...     critical=False,
    ... ).sign(root_key, hashes.SHA256())

Now we can issue an end entity certificate off this chain.

.. doctest::

    >>> ee_key = ec.generate_private_key(ec.SECP256R1())
    >>> subject = x509.Name([
    ...     x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ...     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    ...     x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    ...     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
    ... ])
    >>> ee_cert = x509.CertificateBuilder().subject_name(
    ...     subject
    ... ).issuer_name(
    ...     int_cert.subject
    ... ).public_key(
    ...     ee_key.public_key()
    ... ).serial_number(
    ...     x509.random_serial_number()
    ... ).not_valid_before(
    ...     datetime.datetime.now(datetime.timezone.utc)
    ... ).not_valid_after(
    ...     # Our cert will be valid for 10 days
    ...     datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ... ).add_extension(
    ...     x509.SubjectAlternativeName([
    ...         # Describe what sites we want this certificate for.
    ...         x509.DNSName("cryptography.io"),
    ...         x509.DNSName("www.cryptography.io"),
    ...     ]),
    ...     critical=False,
    ... ).add_extension(
    ...     x509.BasicConstraints(ca=False, path_length=None),
    ...     critical=True,
    ... ).add_extension(
    ...     x509.KeyUsage(
    ...         digital_signature=True,
    ...         content_commitment=False,
    ...         key_encipherment=True,
    ...         data_encipherment=False,
    ...         key_agreement=False,
    ...         key_cert_sign=False,
    ...         crl_sign=True,
    ...         encipher_only=False,
    ...         decipher_only=False,
    ...     ),
    ...     critical=True,
    ... ).add_extension(
    ...     x509.ExtendedKeyUsage([
    ...         x509.ExtendedKeyUsageOID.CLIENT_AUTH,
    ...         x509.ExtendedKeyUsageOID.SERVER_AUTH,
    ...     ]),
    ...     critical=False,
    ... ).add_extension(
    ...     x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key()),
    ...     critical=False,
    ... ).add_extension(
    ...     x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
    ...         int_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    ...     ),
    ...     critical=False,
    ... ).sign(int_key, hashes.SHA256())

And finally we use the verification APIs to validate the chain.

.. doctest::

    >>> from cryptography.x509 import DNSName
    >>> from cryptography.x509.verification import PolicyBuilder, Store
    >>> store = Store([root_cert])
    >>> builder = PolicyBuilder().store(store)
    >>> verifier = builder.build_server_verifier(DNSName("cryptography.io"))
    >>> chain = verifier.verify(ee_cert, [int_cert])
    >>> len(chain)
    3

Determining Certificate or Certificate Signing Request Key Type
---------------------------------------------------------------

Certificates and certificate signing requests can be issued with multiple
key types. You can determine what the key type is by using ``isinstance``
checks:

.. code-block:: pycon

    >>> public_key = cert.public_key()
    >>> if isinstance(public_key, rsa.RSAPublicKey):
    ...     # Do something RSA specific
    ... elif isinstance(public_key, ec.EllipticCurvePublicKey):
    ...     # Do something EC specific
    ... else:
    ...     # Remember to handle this case
