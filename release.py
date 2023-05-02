# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import pathlib
import re
import subprocess

import click


def run(*args: str) -> None:
    print(f"[running] {list(args)}")
    subprocess.check_call(list(args))


@click.group()
def cli():
    pass


@cli.command()
@click.argument("version")
def release(version: str) -> None:
    """
    ``version`` should be a string like '0.4' or '1.0'.
    """
    # Tag and push the tag (this will trigger the wheel builder in Actions)
    run("git", "tag", "-s", version, "-m", f"{version} release")
    run("git", "push", "--tags")


def replace_version(
    p: pathlib.Path, variable_name: str, new_version: str
) -> None:
    with p.open() as f:
        content = f.read()

    pattern = rf"^{variable_name}\s*=\s*.*$"
    match = re.search(pattern, content, re.MULTILINE)
    assert match is not None

    start, end = match.span()
    new_content = (
        content[:start] + f'{variable_name} = "{new_version}"' + content[end:]
    )

    # Write back to file
    with p.open("w") as f:
        f.write(new_content)


@cli.command()
@click.argument("new_version")
def bump_version(new_version: str) -> None:
    base_dir = pathlib.Path(__file__).parent

    replace_version(base_dir / "pyproject.toml", "version", new_version)
    replace_version(
        base_dir / "src/cryptography/__about__.py", "__version__", new_version
    )
    replace_version(
        base_dir / "vectors/pyproject.toml",
        "version",
        new_version,
    )
    replace_version(
        base_dir / "vectors/cryptography_vectors/__about__.py",
        "__version__",
        new_version,
    )


if __name__ == "__main__":
    cli()
