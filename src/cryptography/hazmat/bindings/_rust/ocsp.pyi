from cryptography.x509 import ExtensionType
from cryptography.x509.ocsp import OCSPRequest

def load_der_ocsp_request(data: bytes) -> OCSPRequest: ...
