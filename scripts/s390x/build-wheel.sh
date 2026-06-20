#!/usr/bin/env bash
# Build a manylinux-compatible cryptography wheel on s390x.
#
# Runs inside docker/Dockerfile.s390x. Supports:
#   - local checkout mounted at SOURCE_DIR (default /src)
#   - PyPI sdist via VERSION when SOURCE_DIR is absent or empty
#
# Environment:
#   SOURCE_DIR      Path to cryptography source tree (optional)
#   VERSION         PyPI version to build when not using SOURCE_DIR
#   PYTHON          Python executable (default: python3.12)
#   WHEELHOUSE      Output directory (default: /wheelhouse)
#   MANYLINUX_PLAT  auditwheel platform tag (default: manylinux_2_34_s390x)
#   OPENSSL_VERSION OpenSSL release to build statically (default: 3.4.6)
#   OPENSSL_DIR     Skip OpenSSL build when already provided
#   OPENSSL_STATIC  Set to 1 (default) for release-style wheels

set -euo pipefail

SOURCE_DIR="${SOURCE_DIR:-/src}"
WHEELHOUSE="${WHEELHOUSE:-/wheelhouse}"
PYTHON="${PYTHON:-python3.12}"
MANYLINUX_PLAT="${MANYLINUX_PLAT:-manylinux_2_34_s390x}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.4.6}"
OPENSSL_STATIC="${OPENSSL_STATIC:-1}"
BUILD_REQUIREMENTS="${BUILD_REQUIREMENTS:-.github/requirements/build-requirements.txt}"
WORK="${WORK:-/tmp/cryptography-s390x-build}"

mkdir -p "$WHEELHOUSE"
rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"

echo "=== cryptography s390x wheel build ==="
echo "  python:          $("$PYTHON" --version)"
echo "  arch:            $(uname -m)"
echo "  wheelhouse:      $WHEELHOUSE"
echo "  manylinux plat:  $MANYLINUX_PLAT"
echo "  openssl static:  $OPENSSL_STATIC"

build_static_openssl() {
    if [[ -n "${OPENSSL_DIR:-}" && -d "${OPENSSL_DIR}/include/openssl" ]]; then
        echo "Using prebuilt OpenSSL at ${OPENSSL_DIR}"
        return
    fi

    local ossl_path="${WORK}/openssl"
    echo "Building static OpenSSL ${OPENSSL_VERSION} -> ${ossl_path}"

    export TYPE=openssl
    export VERSION="${OPENSSL_VERSION}"
    export OSSL_PATH="${ossl_path}"
    export CONFIG_FLAGS="${CONFIG_FLAGS:-no-shared no-ssl2 no-ssl3 no-comp no-hw no-engine no-tests}"

    if [[ -f "${SOURCE_DIR}/.github/bin/build_openssl.sh" ]]; then
        bash "${SOURCE_DIR}/.github/bin/build_openssl.sh"
    else
        curl -fsSL \
            "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
            -o "openssl-${OPENSSL_VERSION}.tar.gz"
        tar xzf "openssl-${OPENSSL_VERSION}.tar.gz"
        pushd "openssl-${OPENSSL_VERSION}"
        sed -i "s/^SHLIB_VERSION=.*/SHLIB_VERSION=100/" VERSION.dat
        ./config ${CONFIG_FLAGS} -fPIC --prefix="${OSSL_PATH}"
        make depend
        make -j"$(nproc)"
        make install_sw install_ssldirs
        rm -rf "${OSSL_PATH}/bin"
        popd
    fi

    export OPENSSL_DIR="${ossl_path}"
}

resolve_source_tree() {
    if [[ -d "${SOURCE_DIR}" && -f "${SOURCE_DIR}/pyproject.toml" ]]; then
        echo "Using local source tree: ${SOURCE_DIR}"
        cp -a "${SOURCE_DIR}/." "${WORK}/cryptography-src/"
        SRC="${WORK}/cryptography-src"
        return
    fi

    if [[ -z "${VERSION:-}" ]]; then
        echo "ERROR: set SOURCE_DIR to a checkout or VERSION for a PyPI release." >&2
        exit 1
    fi

    echo "Downloading cryptography==${VERSION} from PyPI"
    "$PYTHON" -m pip download --no-binary ":all:" --no-deps "cryptography==${VERSION}"
    local archive
    archive="$(ls cryptography-*.tar.gz | head -n1)"
    tar xzf "${archive}"
    SRC="$(find . -maxdepth 1 -type d -name 'cryptography-*' | head -n1)"
}

build_wheel() {
    local src="$1"
    local constraints=()
    local out="${WORK}/dist"
    local python_bin
    local py_config

    mkdir -p "$out"

    if [[ -f "${src}/${BUILD_REQUIREMENTS}" ]]; then
        constraints=(--require-hashes --build-constraint="${src}/${BUILD_REQUIREMENTS}")
    fi

    cd "$src"

    python_bin="$(readlink -f "$(command -v "$PYTHON")")"
    py_config="$(command -v "$(basename "$python_bin")-config" || true)"
    if [[ -x "$py_config" ]]; then
        export CFLAGS="${CFLAGS:-} $("$py_config" --includes)"
        export LDFLAGS="${LDFLAGS:-} $("$py_config" --ldflags)"
    fi

    export OPENSSL_DIR="${OPENSSL_DIR:-}"
    export OPENSSL_STATIC="${OPENSSL_STATIC}"
    export PYO3_PYTHON="${python_bin}"

    if command -v uv >/dev/null 2>&1; then
        uv build --wheel "${constraints[@]}" --python "${python_bin}" -o "$out" .
    else
        "$python_bin" -m build --wheel -o "$out" .
    fi

    local wheel
    wheel="$(ls "$out"/cryptography-*.whl | head -n1)"
    echo "Built wheel: ${wheel}"

    auditwheel repair --plat "${MANYLINUX_PLAT}" "${wheel}" -w "$WHEELHOUSE"
}

smoketest_wheel() {
    local wheel
    local src="${WORK}/cryptography-src"
    wheel="$(ls "${WHEELHOUSE}"/cryptography-*.whl | tail -n1)"

    "$PYTHON" -m venv "${WORK}/venv"
    # shellcheck disable=SC1091
    source "${WORK}/venv/bin/activate"
    pip install -U pip

    if [[ -f "${src}/${BUILD_REQUIREMENTS}" ]]; then
        pip install --require-hashes -r "${src}/${BUILD_REQUIREMENTS}"
    else
        pip install "cffi>=2.0.0"
    fi

    pip install --no-index --no-deps "${wheel}"

    python - <<'EOF'
from cryptography.hazmat.backends.openssl.backend import backend

print("Smoketest OK")
print("Loaded:", backend.openssl_version_text())
EOF
}

resolve_source_tree
build_static_openssl
build_wheel "${SRC}"
smoketest_wheel

echo
echo "=== Wheel ready ==="
ls -lh "${WHEELHOUSE}"/cryptography-*.whl
