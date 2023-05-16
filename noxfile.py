# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import glob
import itertools
import json
import pathlib
import re
import sys
import typing
import uuid

import nox

nox.options.reuse_existing_virtualenvs = True


def install(session: nox.Session, *args: str) -> None:
    session.install(
        "-v",
        "-c",
        "ci-constraints-requirements.txt",
        *args,
        silent=False,
    )


@nox.session
@nox.session(name="tests-ssh")
@nox.session(name="tests-randomorder")
@nox.session(name="tests-nocoverage")
def tests(session: nox.Session) -> None:
    extras = "test"
    if session.name == "tests-ssh":
        extras += ",ssh"
    if session.name == "tests-randomorder":
        extras += ",test-randomorder"

    prof_location = (
        pathlib.Path(".") / ".rust-cov" / str(uuid.uuid4())
    ).absolute()
    if session.name != "tests-nocoverage":
        session.env.update(
            {
                "RUSTFLAGS": "-Cinstrument-coverage "
                + session.env.get("RUSTFLAGS", ""),
                "LLVM_PROFILE_FILE": str(prof_location / "cov-%p.profraw"),
            }
        )

    install(session, f".[{extras}]")
    install(session, "-e", "./vectors")

    session.run("pip", "list")

    if session.name != "tests-nocoverage":
        cov_args = [
            "--cov=cryptography",
            "--cov=tests",
        ]
    else:
        cov_args = []

    session.run(
        "pytest",
        "-n",
        "auto",
        "--dist=worksteal",
        *cov_args,
        "--durations=10",
        *session.posargs,
        "tests/",
    )

    if session.name != "tests-nocoverage":
        [rust_so] = glob.glob(
            f"{session.virtualenv.location}/**/cryptography/hazmat/bindings/_rust.*",
            recursive=True,
        )
        process_rust_coverage(session, [rust_so], prof_location)


@nox.session
def docs(session: nox.Session) -> None:
    install(session, ".[docs,docstest,sdist,ssh]")

    temp_dir = session.create_tmp()
    session.run(
        "sphinx-build",
        "-T",
        "-W",
        "-b",
        "html",
        "-d",
        f"{temp_dir}/doctrees",
        "docs",
        "docs/_build/html",
    )
    session.run(
        "sphinx-build",
        "-T",
        "-W",
        "-b",
        "latex",
        "-d",
        f"{temp_dir}/doctrees",
        "docs",
        "docs/_build/latex",
    )

    session.run(
        "sphinx-build",
        "-T",
        "-W",
        "-b",
        "doctest",
        "-d",
        f"{temp_dir}/doctrees",
        "docs",
        "docs/_build/html",
    )
    session.run(
        "sphinx-build",
        "-T",
        "-W",
        "-b",
        "spelling",
        "docs",
        "docs/_build/html",
    )

    # This is in the docs job because `twine check` verifies that the README
    # is valid reStructuredText.
    session.run("python", "-m", "build", "--sdist")
    session.run("twine", "check", "dist/*")


@nox.session(name="docs-linkcheck")
def docs_linkcheck(session: nox.Session) -> None:
    install(session, ".[docs]")

    session.run(
        "sphinx-build", "-W", "-b", "linkcheck", "docs", "docs/_build/html"
    )


@nox.session
def flake(session: nox.Session) -> None:
    install(session, ".[pep8test,test,ssh,nox]")

    session.run("ruff", ".")
    session.run("black", "--check", ".")
    session.run("check-sdist")
    session.run(
        "mypy",
        "src/cryptography/",
        "vectors/cryptography_vectors/",
        "tests/",
        "release.py",
        "noxfile.py",
    )


@nox.session
def rust(session: nox.Session) -> None:
    prof_location = (
        pathlib.Path(".") / ".rust-cov" / str(uuid.uuid4())
    ).absolute()
    session.env.update(
        {
            "RUSTFLAGS": "-Cinstrument-coverage  "
            + session.env.get("RUSTFLAGS", ""),
            "LLVM_PROFILE_FILE": str(prof_location / "cov-%p.profraw"),
        }
    )

    install(session, ".")

    with session.chdir("src/rust/"):
        session.run("cargo", "fmt", "--all", "--", "--check", external=True)
        session.run("cargo", "clippy", "--", "-D", "warnings", external=True)

        build_output = session.run(
            "cargo",
            "test",
            "--no-default-features",
            "--all",
            "--no-run",
            "-q",
            "--message-format=json",
            external=True,
            silent=True,
        )
        session.run(
            "cargo", "test", "--no-default-features", "--all", external=True
        )

    # It's None on install-only invocations
    if build_output is not None:
        assert isinstance(build_output, str)
        rust_tests = []
        for line in build_output.splitlines():
            data = json.loads(line)
            if data.get("profile", {}).get("test", False):
                rust_tests.extend(data["filenames"])

        process_rust_coverage(session, rust_tests, prof_location)


LCOV_SOURCEFILE_RE = re.compile(
    r"^SF:.*[\\/]src[\\/]rust[\\/](.*)$", flags=re.MULTILINE
)
BIN_EXT = ".exe" if sys.platform == "win32" else ""


def process_rust_coverage(
    session: nox.Session,
    rust_binaries: typing.List[str],
    prof_raw_location: pathlib.Path,
) -> None:
    # Hitting weird issues merging Windows and Linux Rust coverage, so just
    # say the hell with it.
    if sys.platform == "win32":
        return

    target_libdir = session.run(
        "rustc", "--print", "target-libdir", external=True, silent=True
    )
    if target_libdir is not None:
        target_bindir = pathlib.Path(target_libdir).parent / "bin"

        profraws = [
            str(prof_raw_location / p)
            for p in prof_raw_location.glob("*.profraw")
        ]
        session.run(
            str(target_bindir / ("llvm-profdata" + BIN_EXT)),
            "merge",
            "-sparse",
            *profraws,
            "-o",
            "rust-cov.profdata",
            external=True,
        )

        lcov_data = session.run(
            str(target_bindir / ("llvm-cov" + BIN_EXT)),
            "export",
            rust_binaries[0],
            *itertools.chain.from_iterable(
                ["-object", b] for b in rust_binaries[1:]
            ),
            "-instr-profile=rust-cov.profdata",
            "--ignore-filename-regex=[/\\].cargo[/\\]",
            "--ignore-filename-regex=[/\\]rustc[/\\]",
            "--ignore-filename-regex=[/\\].rustup[/\\]toolchains[/\\]",
            "--ignore-filename-regex=[/\\]target[/\\]",
            "--format=lcov",
            silent=True,
            external=True,
        )
        assert isinstance(lcov_data, str)
        lcov_data = LCOV_SOURCEFILE_RE.sub(
            lambda m: "SF:src/rust/" + m.group(1).replace("\\", "/"),
            lcov_data.replace("\r\n", "\n"),
        )
        with open(f"{uuid.uuid4()}.lcov", "w") as f:
            f.write(lcov_data)
