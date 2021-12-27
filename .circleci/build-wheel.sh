#!/bin/bash -ex

cd /test

echo "Building for ${PLATFORM}"

PYBIN="/opt/python/${PYTHON}/bin"

mkdir -p /test/wheelhouse.final

"${PYBIN}"/python -m venv .venv

.venv/bin/pip install -U pip wheel cffi setuptools-rust

.venv/bin/python setup.py sdist
cd dist
tar zxf cryptography*.tar.gz
rm -rf cryptograph*.tar.gz
cd cryptography*

REGEX="cp3([0-9])*"
if [[ "${PYBIN}" =~ $REGEX ]]; then
    PY_LIMITED_API="--py-limited-api=cp3${BASH_REMATCH[1]}"
fi

LDFLAGS="-L/opt/pyca/cryptography/openssl/lib" \
       CFLAGS="-I/opt/pyca/cryptography/openssl/include -Wl,--exclude-libs,ALL" \
       ../../.venv/bin/python setup.py bdist_wheel "$PY_LIMITED_API"

auditwheel repair --plat "${PLATFORM}" -w wheelhouse/ dist/cryptography*.whl

../../.venv/bin/pip install cryptography --no-index -f wheelhouse/
../../.venv/bin/python -c "from cryptography.hazmat.backends.openssl.backend import backend;print('Loaded: ' + backend.openssl_version_text());print('Linked Against: ' + backend._ffi.string(backend._lib.OPENSSL_VERSION_TEXT).decode('ascii'))"

mv wheelhouse/* /test/wheelhouse.final
