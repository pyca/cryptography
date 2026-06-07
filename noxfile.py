# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import glob
import hashlib
import itertools
import json
import os
import pathlib
import re
import sys
import uuid

import nox

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

nox.options.reuse_existing_virtualenvs = True
nox.options.default_venv_backend = "uv"


def install(
    session: nox.Session,
    *args: str,
    verbose: bool = True,
) -> None:
    if verbose:
        args += ("-v",)
    session.install(
        "-c",
        "ci-constraints-requirements.txt",
        *args,
        silent=False,
    )


def load_pyproject_toml() -> dict:
    with (pathlib.Path(__file__).parent / "pyproject.toml").open("rb") as f:
        return tomllib.load(f)


def pin_pyo3_config(session: nox.Session) -> None:
    # PEP 517 builds run in a randomly-named temporary environment, and
    # PyO3's build script fingerprints the interpreter path it is given.
    # That makes cargo recompile pyo3 (and everything downstream of it) on
    # every CI run, despite an otherwise warm cache. Resolve the PyO3
    # build config once, against this session's interpreter (whose path is
    # stable from run to run), and pin it via PYO3_CONFIG_FILE so the
    # build is independent of the ephemeral build environment.
    venv = pathlib.Path(session.virtualenv.location)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    output = session.run_install(
        "cargo",
        "check",
        "-p",
        "pyo3-ffi",
        external=True,
        silent=True,
        success_codes=[0, 101],
        env={"PYO3_PRINT_CONFIG": "1", "PYO3_PYTHON": str(python)},
    )
    # None on --no-install invocations, where the config file (and the
    # build it is for) already exists.
    if output is None:
        return
    assert isinstance(output, str)
    config_lines = []
    in_config = False
    for line in output.splitlines():
        line = line.strip()
        if "PYO3_PRINT_CONFIG=1 is set" in line:
            in_config = True
            continue
        if in_config:
            if line.startswith("note:") or "=" not in line:
                break
            config_lines.append(line)
    assert config_lines, f"failed to extract PyO3 config from:\n{output}"
    content = "\n".join(config_lines) + "\n"
    # The file name is content-addressed and the mtime is pinned: cargo
    # treats both a changed PYO3_CONFIG_FILE value and a fresh mtime on
    # the file it points to as reasons to recompile pyo3. This way a
    # regenerated-but-identical config (e.g. a fresh CI run) never looks
    # changed, while a genuinely different config gets a new path.
    digest = hashlib.sha256(content.encode()).hexdigest()[:16]
    config_path = venv / f"pyo3-config-{digest}.txt"
    config_path.write_text(content)
    os.utime(config_path, (0, 0))
    session.env["PYO3_CONFIG_FILE"] = str(config_path)


@nox.session
@nox.session(name="tests-ssh")
@nox.session(name="tests-randomorder")
@nox.session(name="tests-nocoverage")
@nox.session(name="tests-rust-debug")
def tests(session: nox.Session) -> None:
    extras = []
    groups = ["test"]
    if session.name == "tests-ssh":
        extras.append("ssh")
    if session.name == "tests-randomorder":
        groups = ["test-randomorder"]

    prof_location = (
        pathlib.Path(".") / ".rust-cov" / str(uuid.uuid4())
    ).absolute()
    if session.name != "tests-nocoverage":
        rustflags = os.environ.get("RUSTFLAGS", "")
        assert rustflags is not None
        session.env.update(
            {
                "RUSTFLAGS": f"-Cinstrument-coverage {rustflags}",
                "LLVM_PROFILE_FILE": str(prof_location / "cov-%p.profraw"),
            }
        )

    install_spec = f".[{','.join(extras)}]"
    pin_pyo3_config(session)
    install(session, "-e", "./vectors")
    if session.name == "tests-rust-debug":
        install(
            session,
            "--config-settings-package=cryptography:build-args=--profile=dev",
            install_spec,
        )
    else:
        install(session, install_spec)

    install(
        session,
        *itertools.chain.from_iterable(("--group", g) for g in groups),
    )

    session.run("uv", "pip", "list")

    if session.name != "tests-nocoverage":
        cov_args = [
            "--cov=cryptography",
            "--cov=tests",
        ]
    else:
        cov_args = []

    if session.posargs:
        tests = session.posargs
    else:
        tests = ["tests/"]

    session.run(
        "pytest",
        "-n",
        "auto",
        "--dist=worksteal",
        *cov_args,
        "--durations=10",
        *tests,
    )

    if session.name != "tests-nocoverage":
        [rust_so] = glob.glob(
            f"{session.virtualenv.location}/lib/**/cryptography/hazmat/bindings/_rust.*",
            recursive=True,
        )
        process_rust_coverage(session, [rust_so], prof_location)


@nox.session
def docs(session: nox.Session) -> None:
    install(session, ".[ssh]")
    install(
        session,
        "--group",
        "docs",
        "--group",
        "docstest",
        "--group",
        "sdist",
    )

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

    session.run(
        "python3", "-m", "readme_renderer", "README.rst", "-o", "/dev/null"
    )
    session.run(
        "python3",
        "-m",
        "readme_renderer",
        "vectors/README.rst",
        "-o",
        "/dev/null",
    )


@nox.session(name="docs-linkcheck")
def docs_linkcheck(session: nox.Session) -> None:
    install(session, ".", "--group", "docs")

    session.run(
        "sphinx-build", "-W", "-b", "linkcheck", "docs", "docs/_build/html"
    )


@nox.session
def flake(session: nox.Session) -> None:
    # TODO: Ideally there'd be a pip flag to install just our dependencies,
    # but not install us.
    pyproject_data = load_pyproject_toml()
    install(session, "-e", "vectors/")
    install(
        session,
        *pyproject_data["build-system"]["requires"],
        *pyproject_data["project"]["optional-dependencies"]["ssh"],
        "--group",
        "pep8test",
        "--group",
        "test",
        "--group",
        "nox",
    )

    session.run("ruff", "check")
    session.run("ruff", "format", "--check")
    session.run(
        "mypy",
        "src/cryptography/",
        "vectors/cryptography_vectors/",
        "tests/",
        "release.py",
        "noxfile.py",
    )
    session.run("check-sdist", "--no-isolation")


@nox.session
@nox.session(name="rust-noclippy")
def rust(session: nox.Session) -> None:
    prof_location = (
        pathlib.Path(".") / ".rust-cov" / str(uuid.uuid4())
    ).absolute()
    rustflags = os.environ.get("RUSTFLAGS", "")
    assert rustflags is not None
    session.env.update(
        {
            "RUSTFLAGS": f"-Cinstrument-coverage  {rustflags}",
            "LLVM_PROFILE_FILE": str(prof_location / "cov-%p.profraw"),
        }
    )

    # TODO: Ideally there'd be a pip flag to install just our dependencies,
    # but not install us.
    pyproject_data = load_pyproject_toml()
    install(session, *pyproject_data["build-system"]["requires"])

    session.run("cargo", "fmt", "--all", "--", "--check", external=True)
    if session.name != "rust-noclippy":
        session.run(
            "cargo",
            "clippy",
            "--all",
            "--",
            "-D",
            "warnings",
            external=True,
        )

    build_output = session.run(
        "cargo",
        "test",
        "--all",
        "--no-run",
        "-q",
        "--message-format=json",
        external=True,
        silent=True,
    )
    session.run("cargo", "test", "--all", external=True)

    # It's None on install-only invocations
    if build_output is not None:
        assert isinstance(build_output, str)
        rust_tests = []
        for line in build_output.splitlines():
            data = json.loads(line)
            if data.get("profile", {}).get("test", False):
                rust_tests.extend(data["filenames"])

        process_rust_coverage(session, rust_tests, prof_location)


@nox.session
def local(session: nox.Session):
    if "CARGO_INCREMENTAL" not in os.environ:
        session.env["CARGO_INCREMENTAL"] = "1"

    pyproject_data = load_pyproject_toml()
    install(session, "-e", "./vectors", verbose=False)
    install(
        session,
        *pyproject_data["build-system"]["requires"],
        *pyproject_data["project"]["optional-dependencies"]["ssh"],
        *nox.project.dependency_groups(
            pyproject_data, "pep8test", "test", "nox"
        ),
        verbose=False,
    )

    session.run("ruff", "format")
    session.run("ruff", "check")

    session.run("cargo", "fmt", "--all", external=True)
    session.run("cargo", "check", "--all", "--tests", external=True)
    session.run(
        "cargo",
        "clippy",
        "--all",
        "--",
        "-D",
        "warnings",
        external=True,
    )

    session.run(
        "mypy",
        "src/cryptography/",
        "vectors/cryptography_vectors/",
        "tests/",
        "release.py",
        "noxfile.py",
    )

    session.run(
        "maturin",
        "develop",
        "--release",
        "--uv",
    )

    if session.posargs:
        tests = session.posargs
    else:
        tests = ["tests/"]

    session.run(
        "pytest",
        "-n",
        "auto",
        "--dist=worksteal",
        "--durations=10",
        *tests,
    )

    session.run("cargo", "test", "--all", external=True)


LCOV_SOURCEFILE_RE = re.compile(
    r"^SF:.*[\\/]src[\\/]rust[\\/](.*)$", flags=re.MULTILINE
)
BIN_EXT = ".exe" if sys.platform == "win32" else ""


def process_rust_coverage(
    session: nox.Session,
    rust_binaries: list[str],
    prof_raw_location: pathlib.Path,
) -> None:
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
