# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

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
    session.run("python", "setup.py", "sdist")
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
    session.run("check-manifest")
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
    install(session, ".")

    with session.chdir("src/rust/"):
        session.run("cargo", "fmt", "--all", "--", "--check", external=True)
        session.run("cargo", "clippy", "--", "-D", "warnings", external=True)
        session.run("cargo", "test", "--no-default-features", external=True)
