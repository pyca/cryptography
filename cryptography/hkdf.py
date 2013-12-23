from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import constant_time

def hkdf_derive(input_key, key_length, salt=None, info=None, hash=None, backend=None):
    if hash is None:
        hash = hashes.SHA256()

    if backend is None:
        backend = default_backend()

    if info is None:
        info = b""

    if salt is None:
        salt = b"\x00" * (hash.digest_size // 8)

    h = hmac.HMAC(salt, hash, backend=backend)
    h.update(input_key)
    PRK = h.finalize()

    output = [b'']
    counter = 1

    while (hash.digest_size // 8) * len(output) < key_length:
        h = hmac.HMAC(PRK, hash, backend=backend)
        h.update(output[-1])
        h.update(info)
        h.update(chr(counter))
        output.append(h.finalize())
        counter += 1

    return b"".join(output)[:key_length]


def hkdf_verify(expected, input_key, key_length, salt=None, info=None,
                hash=None, backend=None):
    derived = hkdf_derive(input_key, key_length, salt=salt, info=info,
                           hash=hash, backend=backend)

    return constant_time.bytes_eq(expected, derived)

