# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

# /// script
# dependencies = [
#     "click",
#     "packaging",
# ]
# ///

import pathlib
import re
import subprocess
import sys

import click
from packaging.version import Version

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def run(*args: str) -> None:
    print(f"[running] {list(args)}")
    subprocess.check_call(list(args))


@click.group()
def cli():
    pass


@cli.command()
def release() -> None:
    base_dir = pathlib.Path(__file__).parent
    with (base_dir / "pyproject.toml").open("rb") as f:
        pyproject = tomllib.load(f)
        version = pyproject["project"]["version"]

    if Version(version).is_prerelease:
        raise RuntimeError(
            f"Can't release, pyproject.toml version is pre-release: {version}"
        )

    # Tag and push the tag (this will trigger the wheel builder in Actions)
    run("git", "tag", "-s", version, "-m", f"{version} release")
    run("git", "push", "--tags", "git@github.com:pyca/cryptography.git")


def replace_pattern(p: pathlib.Path, pattern: str, replacement: str) -> None:
    content = p.read_text()
    match = re.search(pattern, content, re.MULTILINE)
    assert match is not None

    start, end = match.span()
    new_content = content[:start] + replacement + content[end:]
    p.write_text(new_content)


def replace_version(
    p: pathlib.Path, variable_name: str, new_version: str
) -> None:
    replace_pattern(
        p, rf"^{variable_name}\s*=\s*.*$", f'{variable_name} = "{new_version}"'
    )


def rust_version(version: Version) -> str:
    # The Rust crates use a version that maps to the cryptography version,
    # but pre-1.0: cryptography X.0.Z is version 0.X.Z of the crates.
    if version.minor != 0:
        raise ValueError(
            f"Can't map {version} to a crate version, minor must be 0"
        )
    return f"0.{version.major}.{version.micro}"


def bump_rust_versions(base_dir: pathlib.Path, new_version: str) -> None:
    crate_version = rust_version(Version(new_version))

    with (base_dir / "Cargo.toml").open("rb") as f:
        workspace = tomllib.load(f)["workspace"]

    replace_version(base_dir / "Cargo.toml", "version", crate_version)

    for member in workspace["members"]:
        with (base_dir / member / "Cargo.toml").open("rb") as f:
            crate_name = tomllib.load(f)["package"]["name"]
        replace_pattern(
            base_dir / "Cargo.lock",
            rf'^name = "{crate_name}"\nversion = ".*?"$',
            f'name = "{crate_name}"\nversion = "{crate_version}"',
        )


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

    if Version(new_version).is_prerelease:
        replace_pattern(
            base_dir / "pyproject.toml",
            r'"cryptography_vectors(==.*?)?"',
            '"cryptography_vectors"',
        )
    else:
        replace_pattern(
            base_dir / "pyproject.toml",
            r'"cryptography_vectors(==.*?)?"',
            f'"cryptography_vectors=={new_version}"',
        )

    bump_rust_versions(base_dir, new_version)


if __name__ == "__main__":
    cli()
