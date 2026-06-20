#!/usr/bin/env bash
# Build cryptography s390x wheels using docker + QEMU.
#
# Examples:
#   # From this checkout (recommended while developing the contribution):
#   ./scripts/s390x/build.sh
#
#   # From a tagged PyPI release:
#   VERSION=44.0.0 ./scripts/s390x/build.sh
#
#   # Custom output directory:
#   WHEELHOUSE=$PWD/wheelhouse ./scripts/s390x/build.sh
#
# Environment:
#   IMAGE           Docker image tag (default: cryptography-s390x-builder)
#   SETUP_QEMU      Run setup-qemu.sh first when 1 (default on non-s390x hosts)
#   VERSION         PyPI version when not building from checkout
#   OPENSSL_VERSION Passed through to build-wheel.sh
#   PYTHON          Python executable inside the container

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

IMAGE="${IMAGE:-cryptography-s390x-builder}"
WHEELHOUSE="${WHEELHOUSE:-${ROOT}/wheelhouse}"
PYTHON="${PYTHON:-python3.12}"
HOST_ARCH="$(uname -m)"

mkdir -p "$WHEELHOUSE"

if [[ "${SETUP_QEMU:-}" == "1" || ( "${HOST_ARCH}" != "s390x" && "${SETUP_QEMU:-}" != "0" ) ]]; then
    echo "==> Host arch is ${HOST_ARCH}; ensuring QEMU binfmt for s390x"
    bash "${ROOT}/scripts/s390x/setup-qemu.sh"
fi

echo "==> Building ${IMAGE} for linux/s390x"
docker build --platform linux/s390x \
    -f docker/Dockerfile.s390x \
    -t "${IMAGE}" \
    .

RUN_ARGS=(
    --rm
    --platform linux/s390x
    -v "${ROOT}:/src:ro"
    -v "${WHEELHOUSE}:/wheelhouse"
    -e "SOURCE_DIR=/src"
    -e "WHEELHOUSE=/wheelhouse"
    -e "PYTHON=${PYTHON}"
)

if [[ -n "${VERSION:-}" ]]; then
    RUN_ARGS+=(-e "VERSION=${VERSION}")
fi
if [[ -n "${OPENSSL_VERSION:-}" ]]; then
    RUN_ARGS+=(-e "OPENSSL_VERSION=${OPENSSL_VERSION}")
fi
if [[ -n "${MANYLINUX_PLAT:-}" ]]; then
    RUN_ARGS+=(-e "MANYLINUX_PLAT=${MANYLINUX_PLAT}")
fi

echo "==> Running s390x wheel build"
docker run "${RUN_ARGS[@]}" "${IMAGE}"

echo
echo "Done. Wheels:"
ls -lh "${WHEELHOUSE}"/cryptography-*.whl
