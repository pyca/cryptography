# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

# Set every file in a downloaded artifact to the artifact's own creation
# time. openssl-sys's build script registers cargo:rerun-if-changed on the
# OpenSSL include directory, and cargo evaluates that by mtime, so a
# freshly extracted artifact with identical content would otherwise
# invalidate the cargo cache on every CI run. Using the artifact's
# created_at means an unchanged artifact always looks the same, while a
# rebuilt artifact gets a new timestamp and correctly triggers a rebuild.

import datetime
import os
import sys


def main(root: str, created_at: str) -> None:
    mtime = datetime.datetime.fromisoformat(
        created_at.replace("Z", "+00:00")
    ).timestamp()
    count = 0
    # Directories need pinning too: cargo stats their mtimes as well when
    # evaluating rerun-if-changed on a directory (that's how it notices
    # file deletions), and extraction recreates them fresh on every run.
    for dirpath, _, filenames in os.walk(root):
        for name in (os.curdir, *filenames):
            path = os.path.join(dirpath, name)
            os.utime(path, (mtime, mtime))
            count += 1
    print(f"pinned {count} files in {root} to {created_at}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
