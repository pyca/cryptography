# openssl-bridge

Safe Rust APIs for the OpenSSL operations used by cryptography, supporting
OpenSSL, LibreSSL, BoringSSL, and AWS-LC. The sibling `openssl-bridge-sys`
crate generates FFI from the selected native installation using bindgen.
Neither crate depends on or re-exports rust-openssl or openssl-sys.

Both crates belong to cryptography's root Cargo workspace and use its version,
MSRV, and license. Consumers use workspace dependencies. A separate checkout
or integration patch is no longer needed.

Builds require libclang as well as the selected backend's headers and libraries.
Set `OPENSSL_DIR`, or both `OPENSSL_INCLUDE_DIR` and `OPENSSL_LIB_DIR`;
`OPENSSL_STATIC=1` requests static linking. Otherwise discovery uses pkg-config.
`LIBCLANG_PATH` selects libclang when it is outside the system search path.

Run `nox -e local` from the repository root for formatting, linting, type checks,
the Python suite, and all workspace Rust tests. The `rust` CI session also runs
this crate's integration and documentation tests. Pushes to `openssl-bridge`
run the repository's CI workflow.

[SAFETY.md](SAFETY.md) describes ownership, state, bounds, secret storage,
concurrency, and native-library assumptions. APIs expose owned values and
borrowed slices rather than raw native objects; context copies are fallible,
finalization consumes state, and output bounds are checked before entering C.

The initial implementation and cryptography/CFFI/TLS migration were imported
from [clanker-experiments commit c970d78](https://github.com/reaperhulk/clanker-experiments/tree/c970d7830550134aeddc30ec3144a06fc592fce2/openssl-bridge).
That revision retains the historical backend acceptance reports. New CI results
belong to this repository and must not be inferred from those historical runs.
The companion pyOpenSSL migration is in `.github/patches/pyopenssl.patch`.
