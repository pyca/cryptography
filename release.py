# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import subprocess

import click


def run(*args: str) -> None:
    print(f"[running] {list(args)}")
    subprocess.check_call(list(args))


@click.command()
@click.argument("version")
def release(version: str) -> None:
    """
    ``version`` should be a string like '0.4' or '1.0'.
    """
    # Tag and push the tag (this will trigger the wheel builder in Actions)
    run("git", "tag", "-s", version, "-m", f"{version} release")
    run("git", "push", "--tags")


if __name__ == "__main__":
    release()
