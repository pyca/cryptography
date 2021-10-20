from cryptography.x509 import Extension
from cryptography.x509.ocsp import (
    OCSPRequest,
    OCSPRequestBuilder,
    OCSPResponse,
)

def load_der_ocsp_request(data: bytes) -> OCSPRequest: ...
def load_der_ocsp_response(data: bytes) -> OCSPResponse: ...
def encode_ocsp_basic_response_extension(ext: Extension) -> bytes: ...
def create_ocsp_request(builder: OCSPRequestBuilder) -> OCSPRequest: ...
