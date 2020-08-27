#! /bin/bash

set -e

/opt/python/${PYTHON}/bin/python -m virtualenv .venv
.venv/bin/pip install -U pip wheel cffi six ipaddress
.venv/bin/pip download cryptography==${CRYPTOGRAPHY_VERSION} --no-deps --no-binary cryptography
tar zxvf cryptography*.tar.gz
mkdir tmpwheelhouse

REGEX="cp3([0-9])*"
if [[ "${PYTHON}" =~ $REGEX ]]; then
  PY_LIMITED_API="--py-limited-api=cp3${BASH_REMATCH[1]}"
fi
cd cryptography*
LDFLAGS="-L/opt/pyca/cryptography/openssl/lib" \
CFLAGS="-I/opt/pyca/cryptography/openssl/include -Wl,--exclude-libs,ALL" \
../.venv/bin/python setup.py bdist_wheel $PY_LIMITED_API && mv dist/cryptography*.whl ../tmpwheelhouse
cd ../

auditwheel repair --plat manylinux2014_aarch64 tmpwheelhouse/cryptograp*.whl -w wheelhouse

# execstack not available on manylinux2014_aarch64. Commented out for now
#unzip wheelhouse/*.whl -d execstack.check

#results=$(execstack execstack.check/cryptography/hazmat/bindings/*.so)
#count=$(echo "$results" | grep -c '^X' || true)
#if [ "$count" -ne 0 ]; then
#  exit 1
#else
#  exit 0
#fi

.venv/bin/pip install cryptography --no-index -f wheelhouse/
.venv/bin/python -c "from cryptography.hazmat.backends.openssl.backend import backend;print('Loaded: ' + backend.openssl_version_text());print('Linked Against: ' + backend._ffi.string(backend._lib.OPENSSL_VERSION_TEXT).decode('ascii'))"
