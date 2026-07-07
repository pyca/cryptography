# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

# Makes cached workspace-crate artifacts (Swatinem/rust-cache with
# cache-workspace-crates: true) reusable across CI runs. A fresh checkout
# gives every file and directory the checkout time as its mtime, so cargo
# would consider all cached workspace artifacts stale and rebuild the
# whole workspace on every run. This script pins the mtimes of cargo's
# inputs that are unchanged since the commit the cache was built from to
# a fixed old timestamp, so cargo sees them as older than the cached
# fingerprints. Paths that did change (per git diff) keep their fresh
# checkout mtimes, so cargo rebuilds exactly the crates they belong to.
#
# The anchor file records the commit the cached artifacts were built at.
# It is written at the end of the build and travels in the same cache
# entry as the target directory (via rust-cache's cache-directories), so
# the two cannot disagree. If the anchor is missing or its commit isn't
# fetchable (e.g. an ephemeral pull-request merge commit from an earlier
# run), all mtimes are left alone and cargo rebuilds everything - the
# safe direction.
#
# Requires a checkout with enough history to contain the anchor commit
# (fetch-depth: 0; filter: blob:none keeps that cheap).

import os
import subprocess
import sys

# Everything cargo consults when deciding whether workspace crates are
# fresh: the workspace manifests, the crate sources (including their
# build.rs files), and the paths the build scripts register
# rerun-if-changed on. Anything not listed here keeps its fresh checkout
# mtime, which can only cause rebuilds, never stale reuse.
PATHS = [
    "Cargo.toml",
    "Cargo.lock",
    "src/rust",
    "src/_cffi_src",
    "src/cryptography/__about__.py",
]

# Directories whose mtimes cargo also stats: rerun-if-changed on a
# directory walks it recursively, and directory mtimes are how cargo
# notices file additions and deletions. A directory containing any
# change since the anchor keeps its fresh mtime for that reason.
DIR_ROOTS = ("src/rust", "src/_cffi_src")

# Matches the fixed date the maturin config cache is pinned to in
# .github/actions/cache/action.yml. The exact value is irrelevant; it
# just has to be older than any mtime in the cached target directory.
FIXED_MTIME = 978307200  # 2001-01-01T00:00:00Z


def git_paths(*args: str) -> "set[str]":
    output = subprocess.run(
        ["git", *args, "--", *PATHS],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return {p.decode() for p in output.split(b"\0") if p}


def ancestors_within_roots(path: str) -> "set[str]":
    result = set()
    parent = os.path.dirname(path)
    while any(
        parent == root or parent.startswith(root + "/") for root in DIR_ROOTS
    ):
        result.add(parent)
        parent = os.path.dirname(parent)
    return result


def main(anchor_file: str) -> None:
    try:
        with open(anchor_file) as f:
            anchor = f.read().strip()
    except FileNotFoundError:
        print(f"no anchor at {anchor_file}, leaving mtimes alone")
        return

    if (
        subprocess.run(
            ["git", "cat-file", "-e", f"{anchor}^{{commit}}"],
            stderr=subprocess.DEVNULL,
        ).returncode
        != 0
    ):
        print(f"anchor {anchor} not in history, leaving mtimes alone")
        return

    changed = git_paths(
        "diff", "--name-only", "--no-renames", "-z", anchor, "HEAD"
    )
    tracked = git_paths("ls-files", "-z")

    dirty_dirs = set()
    for path in changed:
        dirty_dirs |= ancestors_within_roots(path)
    all_dirs = set()
    for path in tracked:
        all_dirs |= ancestors_within_roots(path)

    for path in (tracked - changed) | (all_dirs - dirty_dirs):
        os.utime(path, (FIXED_MTIME, FIXED_MTIME))

    print(
        f"pinned {len(tracked - changed)} files and "
        f"{len(all_dirs - dirty_dirs)} directories; "
        f"{len(changed)} paths changed since {anchor[:12]} left fresh"
    )


if __name__ == "__main__":
    main(sys.argv[1])
