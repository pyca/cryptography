# cryptography

Hybrid Python + Rust project. The Python package lives in `src/cryptography/`; the Rust extension (PyO3) lives in `src/rust/`. CFFI bindings to OpenSSL/LibreSSL/BoringSSL/AWS-LC are generated from `src/_cffi_src/`. Test vectors live in `vectors/` (an installable sub-package).

## Running tests

Use `nox -e local` to run the full local check: it formats, lints, and type-checks Python and Rust, then runs the Python and Rust test suites. This is the canonical command — never invoke `pytest` or `cargo test` directly.

Other useful sessions: `nox -e tests`, `nox -e tests-nocoverage`, `nox -e rust`, `nox -e docs`, `nox -e flake`.

To test against different versions of OpenSSL, you can set the `OPENSSL_DIR` environment variable to the path to an OpenSSL/BoringSSL/LibreSSL/AWS-LC installation.

## Package management

Use `uv`, not `pip`, for any Python package installation or environment management. `noxfile.py` already sets `default_venv_backend = "uv"`.

## Changelog

User-visible changes go in `CHANGELOG.rst` under the unreleased section.
