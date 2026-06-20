#!/usr/bin/env bash
# Register QEMU user-mode handlers so docker can run linux/s390x images
# on x86_64, aarch64, or macOS hosts.
#
# Usage: scripts/s390x/setup-qemu.sh

set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is required." >&2
    exit 1
fi

echo "==> Installing binfmt handlers via tonistiigi/binfmt"
docker run --privileged --rm tonistiigi/binfmt --install all

echo "==> Verifying s390x emulation"
docker run --rm --platform linux/s390x quay.io/pypa/manylinux_2_28_s390x uname -m

echo "QEMU s390x is ready."
