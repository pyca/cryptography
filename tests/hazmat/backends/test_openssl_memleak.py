# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import json
import os
import subprocess
import sys
import textwrap

import pytest

from cryptography.hazmat.bindings.openssl.binding import Binding


MEMORY_LEAK_SCRIPT = """
import sys


def main(argv):
    import gc
    import json

    import cffi

    from cryptography.hazmat.bindings._openssl import ffi, lib

    heap = {}

    BACKTRACE_ENABLED = False
    if BACKTRACE_ENABLED:
        backtrace_ffi = cffi.FFI()
        backtrace_ffi.cdef('''
            int backtrace(void **, int);
            char **backtrace_symbols(void *const *, int);
        ''')
        backtrace_lib = backtrace_ffi.dlopen(None)

        def backtrace():
            buf = backtrace_ffi.new("void*[]", 24)
            length = backtrace_lib.backtrace(buf, len(buf))
            return (buf, length)

        def symbolize_backtrace(trace):
            (buf, length) = trace
            symbols = backtrace_lib.backtrace_symbols(buf, length)
            stack = [
                backtrace_ffi.string(symbols[i]).decode()
                for i in range(length)
            ]
            lib.Cryptography_free_wrapper(symbols, backtrace_ffi.NULL, 0)
            return stack
    else:
        def backtrace():
            return None

        def symbolize_backtrace(trace):
            return None

    @ffi.callback("void *(size_t, const char *, int)")
    def malloc(size, path, line):
        ptr = lib.Cryptography_malloc_wrapper(size, path, line)
        heap[ptr] = (size, path, line, backtrace())
        return ptr

    @ffi.callback("void *(void *, size_t, const char *, int)")
    def realloc(ptr, size, path, line):
        if ptr != ffi.NULL:
            del heap[ptr]
        new_ptr = lib.Cryptography_realloc_wrapper(ptr, size, path, line)
        heap[new_ptr] = (size, path, line, backtrace())
        return new_ptr

    @ffi.callback("void(void *, const char *, int)")
    def free(ptr, path, line):
        if ptr != ffi.NULL:
            del heap[ptr]
            lib.Cryptography_free_wrapper(ptr, path, line)

    result = lib.Cryptography_CRYPTO_set_mem_functions(malloc, realloc, free)
    assert result == 1

    # Trigger a bunch of initialization stuff.
    import cryptography.hazmat.backends.openssl

    start_heap = set(heap)

    func(*argv[1:])
    gc.collect()
    gc.collect()
    gc.collect()

    if lib.Cryptography_HAS_OPENSSL_CLEANUP:
        lib.OPENSSL_cleanup()

    # Swap back to the original functions so that if OpenSSL tries to free
    # something from its atexit handle it won't be going through a Python
    # function, which will be deallocated when this function returns
    result = lib.Cryptography_CRYPTO_set_mem_functions(
        ffi.addressof(lib, "Cryptography_malloc_wrapper"),
        ffi.addressof(lib, "Cryptography_realloc_wrapper"),
        ffi.addressof(lib, "Cryptography_free_wrapper"),
    )
    assert result == 1

    remaining = set(heap) - start_heap

    if remaining:
        sys.stdout.write(json.dumps(dict(
            (int(ffi.cast("size_t", ptr)), {
                "size": heap[ptr][0],
                "path": ffi.string(heap[ptr][1]).decode(),
                "line": heap[ptr][2],
                "backtrace": symbolize_backtrace(heap[ptr][3]),
            })
            for ptr in remaining
        )))
        sys.stdout.flush()
        sys.exit(255)

main(sys.argv)
"""


def assert_no_memory_leaks(s, argv=[]):
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(sys.path)

    # When using pytest-cov it attempts to instrument subprocesses. This
    # causes the memleak tests to raise exceptions.
    # we don't need coverage so we remove the env vars.
    env.pop("COV_CORE_CONFIG", None)
    env.pop("COV_CORE_DATAFILE", None)
    env.pop("COV_CORE_SOURCE", None)

    argv = [
        sys.executable,
        "-c",
        "{}\n\n{}".format(s, MEMORY_LEAK_SCRIPT),
    ] + argv
    # Shell out to a fresh Python process because OpenSSL does not allow you to
    # install new memory hooks after the first malloc/free occurs.
    proc = subprocess.Popen(
        argv,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None
    try:
        proc.wait()
        if proc.returncode == 255:
            # 255 means there was a leak, load the info about what mallocs
            # weren't freed.
            out = json.loads(proc.stdout.read().decode())
            raise AssertionError(out)
        elif proc.returncode != 0:
            # Any exception type will do to be honest
            raise ValueError(proc.stdout.read(), proc.stderr.read())
    finally:
        proc.stdout.close()
        proc.stderr.close()


def skip_if_memtesting_not_supported():
    return pytest.mark.skipif(
        not Binding().lib.Cryptography_HAS_MEM_FUNCTIONS,
        reason="Requires OpenSSL memory functions (>=1.1.0)",
    )


@pytest.mark.skip_fips(reason="FIPS self-test sets allow_customize = 0")
@skip_if_memtesting_not_supported()
class TestAssertNoMemoryLeaks(object):
    def test_no_leak_no_malloc(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            pass
        """
            )
        )

    def test_no_leak_free(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            from cryptography.hazmat.bindings.openssl.binding import Binding
            b = Binding()
            name = b.lib.X509_NAME_new()
            b.lib.X509_NAME_free(name)
        """
            )
        )

    def test_no_leak_gc(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            from cryptography.hazmat.bindings.openssl.binding import Binding
            b = Binding()
            name = b.lib.X509_NAME_new()
            b.ffi.gc(name, b.lib.X509_NAME_free)
        """
            )
        )

    def test_leak(self):
        with pytest.raises(AssertionError):
            assert_no_memory_leaks(
                textwrap.dedent(
                    """
            def func():
                from cryptography.hazmat.bindings.openssl.binding import (
                    Binding
                )
                b = Binding()
                b.lib.X509_NAME_new()
            """
                )
            )

    def test_errors(self):
        with pytest.raises(ValueError):
            assert_no_memory_leaks(
                textwrap.dedent(
                    """
            def func():
                raise ZeroDivisionError
            """
                )
            )


@pytest.mark.skip_fips(reason="FIPS self-test sets allow_customize = 0")
@skip_if_memtesting_not_supported()
class TestOpenSSLMemoryLeaks(object):
    @pytest.mark.parametrize(
        "path", ["x509/PKITS_data/certs/ValidcRLIssuerTest28EE.crt"]
    )
    def test_der_x509_certificate_extensions(self, path):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func(path):
            from cryptography import x509
            from cryptography.hazmat.backends.openssl import backend

            import cryptography_vectors

            with cryptography_vectors.open_vector_file(path, "rb") as f:
                cert = x509.load_der_x509_certificate(
                    f.read(), backend
                )

            cert.extensions
        """
            ),
            [path],
        )

    @pytest.mark.parametrize("path", ["x509/cryptography.io.pem"])
    def test_pem_x509_certificate_extensions(self, path):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func(path):
            from cryptography import x509
            from cryptography.hazmat.backends.openssl import backend

            import cryptography_vectors

            with cryptography_vectors.open_vector_file(path, "rb") as f:
                cert = x509.load_pem_x509_certificate(
                    f.read(), backend
                )

            cert.extensions
        """
            ),
            [path],
        )

    def test_x509_csr_extensions(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            from cryptography import x509
            from cryptography.hazmat.backends.openssl import backend
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa

            private_key = rsa.generate_private_key(
                key_size=2048, public_exponent=65537, backend=backend
            )
            cert = x509.CertificateSigningRequestBuilder().subject_name(
                x509.Name([])
            ).add_extension(
               x509.OCSPNoCheck(), critical=False
            ).sign(private_key, hashes.SHA256(), backend)

            cert.extensions
        """
            )
        )

    def test_ec_private_numbers_private_key(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            from cryptography.hazmat.backends.openssl import backend
            from cryptography.hazmat.primitives.asymmetric import ec

            ec.EllipticCurvePrivateNumbers(
                private_value=int(
                    '280814107134858470598753916394807521398239633534281633982576099083'
                    '35787109896602102090002196616273211495718603965098'
                ),
                public_numbers=ec.EllipticCurvePublicNumbers(
                    curve=ec.SECP384R1(),
                    x=int(
                        '10036914308591746758780165503819213553101287571902957054148542'
                        '504671046744460374996612408381962208627004841444205030'
                    ),
                    y=int(
                        '17337335659928075994560513699823544906448896792102247714689323'
                        '575406618073069185107088229463828921069465902299522926'
                    )
                )
            ).private_key(backend)
        """
            )
        )

    def test_ec_derive_private_key(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            from cryptography.hazmat.backends.openssl import backend
            from cryptography.hazmat.primitives.asymmetric import ec
            ec.derive_private_key(1, ec.SECP256R1(), backend)
        """
            )
        )

    def test_x25519_pubkey_from_private_key(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            from cryptography.hazmat.primitives.asymmetric import x25519
            private_key = x25519.X25519PrivateKey.generate()
            private_key.public_key()
        """
            )
        )

    def test_create_ocsp_request(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            from cryptography import x509
            from cryptography.hazmat.backends.openssl import backend
            from cryptography.hazmat.primitives import hashes
            from cryptography.x509 import ocsp
            import cryptography_vectors

            path = "x509/PKITS_data/certs/ValidcRLIssuerTest28EE.crt"
            with cryptography_vectors.open_vector_file(path, "rb") as f:
                cert = x509.load_der_x509_certificate(
                    f.read(), backend
                )
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(
                cert, cert, hashes.SHA1()
            ).add_extension(x509.OCSPNonce(b"0000"), False)
            req = builder.build()
        """
            )
        )

    @pytest.mark.parametrize(
        "path",
        ["pkcs12/cert-aes256cbc-no-key.p12", "pkcs12/cert-key-aes256cbc.p12"],
    )
    def test_load_pkcs12_key_and_certificates(self, path):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func(path):
            from cryptography import x509
            from cryptography.hazmat.backends.openssl import backend
            from cryptography.hazmat.primitives.serialization import pkcs12
            import cryptography_vectors

            with cryptography_vectors.open_vector_file(path, "rb") as f:
                pkcs12.load_key_and_certificates(
                    f.read(), b"cryptography", backend
                )
        """
            ),
            [path],
        )

    def test_create_crl_with_idp(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            import datetime
            from cryptography import x509
            from cryptography.hazmat.backends.openssl import backend
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import NameOID

            key = ec.generate_private_key(ec.SECP256R1(), backend)
            last_update = datetime.datetime(2002, 1, 1, 12, 1)
            next_update = datetime.datetime(2030, 1, 1, 12, 1)
            idp = x509.IssuingDistributionPoint(
                full_name=None,
                relative_name=x509.RelativeDistinguishedName([
                    x509.NameAttribute(
                        oid=x509.NameOID.ORGANIZATION_NAME, value=u"PyCA")
                ]),
                only_contains_user_certs=False,
                only_contains_ca_certs=True,
                only_some_reasons=None,
                indirect_crl=False,
                only_contains_attribute_certs=False,
            )
            builder = x509.CertificateRevocationListBuilder().issuer_name(
                x509.Name([
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, u"cryptography.io CA"
                    )
                ])
            ).last_update(
                last_update
            ).next_update(
                next_update
            ).add_extension(
                idp, True
            )

            crl = builder.sign(key, hashes.SHA256(), backend)
            crl.extensions.get_extension_for_class(
                x509.IssuingDistributionPoint
            )
        """
            )
        )

    def test_create_certificate_with_extensions(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            import datetime

            from cryptography import x509
            from cryptography.hazmat.backends.openssl import backend
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import (
                AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID
            )

            private_key = ec.generate_private_key(ec.SECP256R1(), backend)

            not_valid_before = datetime.datetime.now()
            not_valid_after = not_valid_before + datetime.timedelta(days=365)

            aia = x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(u"http://ocsp.domain.com")
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier(u"http://domain.com/ca.crt")
                )
            ])
            sans = [u'*.example.org', u'foobar.example.net']
            san = x509.SubjectAlternativeName(list(map(x509.DNSName, sans)))

            ski = x509.SubjectKeyIdentifier.from_public_key(
                private_key.public_key()
            )
            eku = x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CODE_SIGNING,
            ])

            builder = x509.CertificateBuilder().serial_number(
                777
            ).issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])).subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])).public_key(
                private_key.public_key()
            ).add_extension(
                aia, critical=False
            ).not_valid_before(
                not_valid_before
            ).not_valid_after(
                not_valid_after
            )

            cert = builder.sign(private_key, hashes.SHA256(), backend)
            cert.extensions
        """
            )
        )

    def test_write_pkcs12_key_and_certificates(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            import os
            from cryptography import x509
            from cryptography.hazmat.backends.openssl import backend
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import pkcs12
            import cryptography_vectors

            path = os.path.join('x509', 'custom', 'ca', 'ca.pem')
            with cryptography_vectors.open_vector_file(path, "rb") as f:
                cert = x509.load_pem_x509_certificate(
                    f.read(), backend
                )
            path2 = os.path.join('x509', 'custom', 'dsa_selfsigned_ca.pem')
            with cryptography_vectors.open_vector_file(path2, "rb") as f:
                cert2 = x509.load_pem_x509_certificate(
                    f.read(), backend
                )
            path3 = os.path.join('x509', 'letsencryptx3.pem')
            with cryptography_vectors.open_vector_file(path3, "rb") as f:
                cert3 = x509.load_pem_x509_certificate(
                    f.read(), backend
                )
            key_path = os.path.join("x509", "custom", "ca", "ca_key.pem")
            with cryptography_vectors.open_vector_file(key_path, "rb") as f:
                key = serialization.load_pem_private_key(
                    f.read(), None, backend
                )
            encryption = serialization.NoEncryption()
            pkcs12.serialize_key_and_certificates(
                b"name", key, cert, [cert2, cert3], encryption)
        """
            )
        )
