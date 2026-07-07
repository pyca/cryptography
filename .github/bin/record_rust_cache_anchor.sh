#!/bin/sh
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

# Records which commit the Rust artifacts in target/ were built from and
# stashes the workspace cdylib, which rust-cache's cleanup would
# otherwise drop from the cache. Both live in .rust-build-meta, which is
# cached in the same entry as the target directory (see
# .github/actions/cache/action.yml and prepare_rust_cache_mtimes.py), so
# they cannot fall out of sync with the artifacts they describe. Run at
# the end of every CI step that builds the extension.
set -e

mkdir -p .rust-build-meta/artifacts/deps
git rev-parse HEAD > .rust-build-meta/anchor-commit
cp -p target/release/deps/*cryptography_rust* \
    .rust-build-meta/artifacts/deps/ 2>/dev/null || true
