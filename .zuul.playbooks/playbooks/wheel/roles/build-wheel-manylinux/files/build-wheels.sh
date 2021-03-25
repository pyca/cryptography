#!/bin/bash -ex

# Compile wheels
cd /io

mkdir -p wheelhouse.final

for P in ${PYTHONS}; do

    PYBIN=/opt/python/${P}/bin

    "${PYBIN}"/python -m venv .venv

    .venv/bin/pip install -U pip wheel cffi setuptools-rust

    REGEX="cp3([0-9])*"
    if [[ "${PYBIN}" =~ $REGEX ]]; then
        PY_LIMITED_API="--py-limited-api=cp3${BASH_REMATCH[1]}"
    fi

    LDFLAGS="-L/opt/pyca/cryptography/openssl/lib" \
           CFLAGS="-I/opt/pyca/cryptography/openssl/include -Wl,--exclude-libs,ALL" \
           .venv/bin/python setup.py bdist_wheel $PY_LIMITED_API

    auditwheel repair --plat ${PLAT} -w wheelhouse/ dist/cryptography*.whl

    # Sanity checks
    # NOTE(ianw) : no execstack on aarch64, comes from
    # prelink, which was never supported.  CentOS 8 does
    # have it separate, skip for now.
    if [[ "${PLAT}" != "manylinux2014_aarch64" ]]; then
        for f in wheelhouse/*.whl; do
            unzip $f -d execstack.check

            results=$(execstack execstack.check/cryptography/hazmat/bindings/*.so)
            count=$(echo "$results" | grep -c '^X' || true)
            if [ "$count" -ne 0 ]; then
                exit 1
            fi
            rm -rf execstack.check
        done
    fi

    .venv/bin/pip install cryptography --no-index -f wheelhouse/
    .venv/bin/python -c "from cryptography.hazmat.backends.openssl.backend import backend;print('Loaded: ' + backend.openssl_version_text());print('Linked Against: ' + backend._ffi.string(backend._lib.OPENSSL_VERSION_TEXT).decode('ascii'))"

    # Cleanup
    mv wheelhouse/* wheelhouse.final
    rm -rf .venv dist wheelhouse

done
