# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import os
import pathlib
import platform
import sys

# Add the src directory to the path so we can import _cffi_src.utils
src_dir = str(pathlib.Path(__file__).parent.parent)
sys.path.insert(0, src_dir)

from _cffi_src.utils import build_ffi_for_binding  # noqa: E402

ffi = build_ffi_for_binding(
    module_name="_openssl",
    module_prefix="_cffi_src.openssl.",
    modules=[
        # This goes first so we can define some cryptography-wide symbols.
        "cryptography",
        # Provider comes early as well so we define OSSL_LIB_CTX
        "provider",
        "asn1",
        "bignum",
        "bio",
        "cmac",
        "crypto",
        "dh",
        "dsa",
        "ec",
        "engine",
        "err",
        "evp",
        "evp_aead",
        "fips",
        "nid",
        "objects",
        "opensslv",
        "pem",
        "pkcs12",
        "rand",
        "rsa",
        "ssl",
        "x509",
        "x509name",
        "x509v3",
        "x509_vfy",
        "pkcs7",
        "callbacks",
    ],
)

if __name__ == "__main__":
    out_dir = os.environ["OUT_DIR"]
    module_name, source, source_extension, kwds = ffi._assigned_source
    c_file = os.path.join(out_dir, module_name + source_extension)
    if platform.python_implementation() == "PyPy":
        # Necessary because CFFI will ignore this if there's no declarations.
        ffi.embedding_api(
            """
            extern "Python" void Cryptography_unused(void);
        """
        )
        ffi.embedding_init_code("")
    ffi.emit_c_code(c_file)
