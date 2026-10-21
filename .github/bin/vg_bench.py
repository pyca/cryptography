# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""Benchmarks cryptography's public API on whichever backend it was built with,
to compare the verified-garbage and OpenSSL-family backends (see
VERIFIED_GARBAGE.md).

Usage: python vg_bench.py OUT.json

The X.509 benchmarks read a certificate chain from cryptography_vectors.

Each operation runs in rounds of about ROUND_SECONDS; the result is the median
time per operation over ROUNDS rounds. Operations the backend does not support
are recorded as null.
"""

import json
import os
import statistics
import sys
import time

from cryptography import x509
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import (
    cmac,
    hashes,
    hmac,
    poly1305,
    serialization,
)
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    mldsa,
    mlkem,
    rsa,
    x448,
    x25519,
)
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import (
    AESCCM,
    AESGCM,
    AESGCMSIV,
    AESOCB3,
    AESSIV,
    ChaCha20Poly1305,
)
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ROUNDS = 7
ROUND_SECONDS = 0.15

SIZES = {"64B": 64, "1KiB": 1024, "1MiB": 1024 * 1024}


def measure(fn):
    """The median seconds per call of `fn`."""
    fn()  # warm up
    # Calibrate the number of calls per round.
    n = 1
    while True:
        t = time.perf_counter()
        for _ in range(n):
            fn()
        dt = time.perf_counter() - t
        if dt >= ROUND_SECONDS / 4 or n >= 1 << 24:
            break
        n *= 4
    n = max(1, int(n * ROUND_SECONDS / max(dt, 1e-9)))
    per_call = []
    for _ in range(ROUNDS):
        t = time.perf_counter()
        for _ in range(n):
            fn()
        per_call.append((time.perf_counter() - t) / n)
    return statistics.median(per_call)


results = {}


def bench(name, setup):
    """Runs `setup()`, which returns the function to time."""
    try:
        fn = setup()
        results[name] = measure(fn)
    except Exception as e:  # unsupported on this backend
        results[name] = None
        print(f"  {name}: n/a ({type(e).__name__}: {e})", file=sys.stderr)


def data(n):
    return os.urandom(n)


# Hashes and MACs
def hash_once(alg, d):
    h = hashes.Hash(alg)
    h.update(d)
    return h.finalize()


for alg in [
    hashes.SHA256(),
    hashes.SHA512(),
    hashes.SHA3_256(),
    hashes.BLAKE2b(64),
]:
    for label, n in SIZES.items():
        bench(
            f"hash/{alg.name}/{label}",
            lambda alg=alg, n=n: lambda d=data(n): hash_once(alg, d),
        )


def hmac_once(key, alg, d):
    h = hmac.HMAC(key, alg)
    h.update(d)
    return h.finalize()


for label, n in SIZES.items():
    bench(
        f"hmac/sha256/{label}",
        lambda n=n: (
            lambda k=data(32), d=data(n): hmac_once(k, hashes.SHA256(), d)
        ),
    )
    bench(
        f"poly1305/{label}",
        lambda n=n: (
            lambda k=data(32), d=data(n): poly1305.Poly1305.generate_tag(k, d)
        ),
    )


def cmac_once(key, d):
    c = cmac.CMAC(algorithms.AES(key))
    c.update(d)
    return c.finalize()


for label, n in SIZES.items():
    bench(
        f"cmac/aes128/{label}",
        lambda n=n: lambda k=data(16), d=data(n): cmac_once(k, d),
    )

# AEADs
aeads = {
    "aesgcm-128": (lambda: AESGCM(data(16)), 12),
    "aesgcm-256": (lambda: AESGCM(data(32)), 12),
    "chacha20poly1305": (lambda: ChaCha20Poly1305(data(32)), 12),
    "aesccm-128": (lambda: AESCCM(data(16)), 12),
    "aesgcmsiv-256": (lambda: AESGCMSIV(data(32)), 12),
    "aesocb3-128": (lambda: AESOCB3(data(16)), 12),
    "aessiv-256": (lambda: AESSIV(data(32)), None),
}
for name, (make, nlen) in aeads.items():
    for label, n in SIZES.items():

        def setup_enc(make=make, nlen=nlen, n=n):
            a, d = make(), data(n)
            if nlen is None:
                return lambda: a.encrypt(d, [b"aad"])
            nonce = data(nlen)
            return lambda: a.encrypt(nonce, d, b"aad")

        def setup_dec(make=make, nlen=nlen, n=n):
            a, d = make(), data(n)
            if nlen is None:
                ct = a.encrypt(d, [b"aad"])
                return lambda: a.decrypt(ct, [b"aad"])
            nonce = data(nlen)
            ct = a.encrypt(nonce, d, b"aad")
            return lambda: a.decrypt(nonce, ct, b"aad")

        bench(f"aead/{name}/encrypt/{label}", setup_enc)
        bench(f"aead/{name}/decrypt/{label}", setup_dec)

# Ciphers (streaming API)
ciphers = {
    "aes128-ctr": lambda: Cipher(
        algorithms.AES(data(16)), modes.CTR(data(16))
    ),
    "aes128-cbc": lambda: Cipher(
        algorithms.AES(data(16)), modes.CBC(data(16))
    ),
    "aes256-xts": lambda: Cipher(
        algorithms.AES(data(64)), modes.XTS(data(16))
    ),
    "chacha20": lambda: Cipher(algorithms.ChaCha20(data(32), data(16)), None),
}
for name, make in ciphers.items():
    for label, n in SIZES.items():

        def setup_cipher(make=make, n=n):
            c, d = make(), data(n)

            def run():
                e = c.encryptor()
                e.update(d)
                e.finalize()

            return run

        bench(f"cipher/{name}/encrypt/{label}", setup_cipher)

# KDFs
bench(
    "kdf/pbkdf2-sha256/100000",
    lambda: (
        lambda: PBKDF2HMAC(hashes.SHA256(), 32, b"salt", 100_000).derive(b"pw")
    ),
)
bench(
    "kdf/scrypt/n=2^14,r=8,p=1",
    lambda: lambda: Scrypt(b"salt", 32, 2**14, 8, 1).derive(b"pw"),
)
bench(
    "kdf/argon2id/m=64MiB,t=3,p=4",
    lambda: (
        lambda: Argon2id(
            salt=b"saltsalt",
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=65536,
        ).derive(b"pw")
    ),
)
bench(
    "kdf/hkdf-sha256/32B",
    lambda: lambda: HKDF(hashes.SHA256(), 32, b"s", b"i").derive(b"k" * 32),
)

# Fernet
from cryptography.fernet import Fernet  # noqa: E402

bench(
    "fernet/encrypt/1KiB",
    lambda f=Fernet(Fernet.generate_key()), d=data(1024): lambda: f.encrypt(d),
)
bench(
    "fernet/decrypt/1KiB",
    lambda f=Fernet(Fernet.generate_key()), d=data(1024): (
        lambda t=f.encrypt(d): f.decrypt(t)
    ),
)

# Signatures and key agreement
msg = data(64)

bench("ed25519/keygen", lambda: ed25519.Ed25519PrivateKey.generate)
bench(
    "ed25519/sign",
    lambda k=None: lambda k=ed25519.Ed25519PrivateKey.generate(): k.sign(msg),
)


def ed_verify(mod):
    k = mod.generate()
    s = k.sign(msg)
    p = k.public_key()
    return lambda: p.verify(s, msg)


bench("ed25519/verify", lambda: ed_verify(ed25519.Ed25519PrivateKey))
bench(
    "ed448/sign",
    lambda: lambda k=ed448.Ed448PrivateKey.generate(): k.sign(msg),
)
bench("ed448/verify", lambda: ed_verify(ed448.Ed448PrivateKey))


def xdh(mod):
    a, b = mod.generate(), mod.generate().public_key()
    return lambda: a.exchange(b)


bench("x25519/keygen", lambda: x25519.X25519PrivateKey.generate)
bench("x25519/exchange", lambda: xdh(x25519.X25519PrivateKey))
bench("x448/exchange", lambda: xdh(x448.X448PrivateKey))

curves = [
    ("p256", ec.SECP256R1, hashes.SHA256),
    ("p384", ec.SECP384R1, hashes.SHA384),
    ("p521", ec.SECP521R1, hashes.SHA512),
    ("secp256k1", ec.SECP256K1, hashes.SHA256),
]
for name, curve, h in curves:
    bench(
        f"ecdsa/{name}/keygen",
        lambda curve=curve: lambda: ec.generate_private_key(curve()),
    )

    def setup_sign(curve=curve, h=h):
        k = ec.generate_private_key(curve())
        return lambda: k.sign(msg, ec.ECDSA(h()))

    def setup_verify(curve=curve, h=h):
        k = ec.generate_private_key(curve())
        s = k.sign(msg, ec.ECDSA(h()))
        p = k.public_key()
        return lambda: p.verify(s, msg, ec.ECDSA(h()))

    def setup_ecdh(curve=curve):
        a = ec.generate_private_key(curve())
        b = ec.generate_private_key(curve()).public_key()
        return lambda: a.exchange(ec.ECDH(), b)

    bench(f"ecdsa/{name}/sign", setup_sign)
    bench(f"ecdsa/{name}/verify", setup_verify)
    bench(f"ecdh/{name}/exchange", setup_ecdh)

pss = apad.PSS(apad.MGF1(hashes.SHA256()), apad.PSS.DIGEST_LENGTH)
oaep = apad.OAEP(apad.MGF1(hashes.SHA256()), hashes.SHA256(), None)
rsa_keys = {}
for bits in [2048, 3072, 4096]:
    rsa_keys[bits] = rsa.generate_private_key(65537, bits)

    def setup_rsa_sign(bits=bits, p=None):
        k = rsa_keys[bits]
        return lambda: k.sign(msg, pss, hashes.SHA256())

    def setup_rsa_sign_v15(bits=bits):
        k = rsa_keys[bits]
        return lambda: k.sign(msg, apad.PKCS1v15(), hashes.SHA256())

    def setup_rsa_verify(bits=bits):
        k = rsa_keys[bits]
        s = k.sign(msg, pss, hashes.SHA256())
        p = k.public_key()
        return lambda: p.verify(s, msg, pss, hashes.SHA256())

    def setup_rsa_decrypt(bits=bits):
        k = rsa_keys[bits]
        ct = k.public_key().encrypt(b"x" * 32, oaep)
        return lambda: k.decrypt(ct, oaep)

    def setup_rsa_encrypt(bits=bits):
        p = rsa_keys[bits].public_key()
        return lambda: p.encrypt(b"x" * 32, oaep)

    bench(f"rsa/{bits}/sign-pss", setup_rsa_sign)
    bench(f"rsa/{bits}/sign-pkcs1v15", setup_rsa_sign_v15)
    bench(f"rsa/{bits}/verify-pss", setup_rsa_verify)
    bench(f"rsa/{bits}/encrypt-oaep", setup_rsa_encrypt)
    bench(f"rsa/{bits}/decrypt-oaep", setup_rsa_decrypt)

bench("rsa/2048/keygen", lambda: lambda: rsa.generate_private_key(65537, 2048))


def setup_rsa_load(bits=2048):
    pem = rsa_keys[bits].private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return lambda: serialization.load_pem_private_key(pem, None)


bench("rsa/2048/load-pem-private-key", setup_rsa_load)

for name, gen in [
    ("mlkem768", mlkem.MLKEM768PrivateKey.generate),
    ("mlkem1024", mlkem.MLKEM1024PrivateKey.generate),
]:
    bench(f"{name}/keygen", lambda gen=gen: gen)

    def setup_encap(gen=gen):
        p = gen().public_key()
        return lambda: p.encapsulate()

    def setup_decap(gen=gen):
        k = gen()
        _, ct = k.public_key().encapsulate()
        return lambda: k.decapsulate(ct)

    bench(f"{name}/encapsulate", setup_encap)
    bench(f"{name}/decapsulate", setup_decap)

for name, gen in [
    ("mldsa44", mldsa.MLDSA44PrivateKey.generate),
    ("mldsa65", mldsa.MLDSA65PrivateKey.generate),
    ("mldsa87", mldsa.MLDSA87PrivateKey.generate),
]:
    bench(f"{name}/keygen", lambda gen=gen: gen)

    def setup_mldsa_sign(gen=gen):
        k = gen()
        return lambda: k.sign(msg)

    def setup_mldsa_verify(gen=gen):
        k = gen()
        s = k.sign(msg)
        p = k.public_key()
        return lambda: p.verify(s, msg)

    bench(f"{name}/sign", setup_mldsa_sign)
    bench(f"{name}/verify", setup_mldsa_verify)


# X.509
def x509_chain():
    import cryptography_vectors

    with cryptography_vectors.open_vector_file(
        os.path.join("x509", "cryptography.io.chain.pem"), "rb"
    ) as f:
        return x509.load_pem_x509_certificates(f.read())


def setup_x509_load():
    der = x509_chain()[0].public_bytes(serialization.Encoding.DER)
    return lambda: x509.load_der_x509_certificate(der)


def setup_x509_verify():
    cert, issuer = x509_chain()[:2]
    return lambda: cert.verify_directly_issued_by(issuer)


bench("x509/load-der", setup_x509_load)
bench("x509/verify-directly-issued-by", setup_x509_verify)

backend = (
    "verified-garbage"
    if rust_openssl.CRYPTOGRAPHY_IS_VERIFIED_GARBAGE
    else rust_openssl.openssl_version_text()
)
with open(sys.argv[1], "w") as f:
    json.dump({"backend": backend, "results": results}, f, indent=1)
print(f"{backend}: {sum(v is not None for v in results.values())} benchmarks")
