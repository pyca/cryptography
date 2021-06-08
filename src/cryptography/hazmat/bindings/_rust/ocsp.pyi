from cryptography.x509 import ExtensionType
from cryptography.x509.ocsp import OCSPRequest

def load_der_ocsp_request(data: bytes) -> OCSPRequest: ...
def parse_ocsp_resp_extension(
    der_oid: bytes, ext_data: bytes
) -> ExtensionType: ...
def parse_ocsp_singleresp_extension(
    der_oid: bytes, ext_data: bytes
) -> ExtensionType: ...
