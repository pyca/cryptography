from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
password_rsa=b"MiPasswordHolaMundo"
key_rsa = rsa.generate_private_key(
    public_exponent=65537,
    key_size=8192,
    backend=default_backend()
)
with open("./rsa_self_certificate_private_key.pem","wb") as popen:
    popen.write(key_rsa.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(password_rsa),
))
subject_for_certificate = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME,u"MX"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,u"Michoacan"),
    x509.NameAttribute(NameOID.LOCALITY_NAME,u"Uruapan"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,u"Cryptology"),
    x509.NameAttribute(NameOID.COMMON_NAME,u"127.0.0.1"),
])
cert = x509.CertificateBuilder().subject_name(
        subject_for_certificate
    ).issuer_name(
        subject_for_certificate
    ).public_key(
        key_rsa.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=650)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
).sign(key_rsa, hashes.SHA3_512(), default_backend())
with open("./rsa_self_certificate_csr.pem", "wb") as popen:
    popen.write(cert.public_bytes(serialization.Encoding.PEM))