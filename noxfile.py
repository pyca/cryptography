# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import glob
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

    session.run(
        "pytest",
        "-n",
        "auto",
        "--dist=worksteal",
        *cov_args,
        "--durations=10",
        *session.posargs,
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

    session.run(
        "pytest",
        "-n",
        "auto",
        "--dist=worksteal",
        "--durations=10",
        *session.posargs,
    )

    session.run("cargo", "test", "--all", external=True)


LCOV_SOURCEFILE_RE = re.compile(
    r"^SF:.*[\\/]src[\\/]rust[\\/](.*)$", flags=re.MULTILINE
)
BIN_EXT = ".exe" if sys.platform == "win32" else ""


def _parse_profdata_function_counts(prof_dump: str) -> dict[str, int]:
    # Parses `llvm-profdata show --all-functions` output, which contains
    # a block like this for every instrumented function:
    #   <mangled name>:
    #     Hash: 0x0123456789abcdef
    #     Counters: 7
    #     Function count: 8
    counts: dict[str, int] = {}
    name = None
    for line in prof_dump.splitlines():
        if line.startswith("  ") and not line.startswith("    "):
            name = line.strip().removesuffix(":")
        elif name is not None and line.strip().startswith("Function count: "):
            count = int(line.rsplit(":", 1)[1])
            counts[name] = max(counts.get(name, 0), count)
            name = None
    return counts


def _repair_expanded_code_coverage(
    lcov_data: str, prof_counts: dict[str, int]
) -> str:
    """
    Starting with Rust 1.84, a function consisting entirely of
    proc-macro expanded code (e.g. the impls generated by
    ``#[derive(...)]`` or ``#[pyo3::pymethods]``) gets a coverage
    mapping containing only a residual region on the attribute line,
    wired to a counter that never executes. llvm-cov therefore reports
    the function -- and with it the attribute line -- as unexecuted,
    even when the raw profile proves the function ran (its counters
    are live; only the mapping is defective). We repair the two ways
    this corrupts line coverage:

    - If the raw profile's count for a function disagrees with the
      lcov function summary (FNDA), trust the profile and mark the
      function's start line as executed.
    - If every function on a zero-count line is absent from the raw
      profile, the compiler emitted only "unused function" placeholder
      records for macro-generated impls that were never codegen'd
      (e.g. an unused generated trait impl); the line's executability
      is an artifact of the residual region, so drop it. Handwritten
      dead code is unaffected: it is codegen'd, so it registers a
      profile record (with count 0) and its body lines keep their
      zero-count records either way.
    """
    result: list[str] = []
    record: list[str] = []
    for line in lcov_data.splitlines():
        record.append(line)
        if line == "end_of_record":
            result.extend(_repair_lcov_record(record, prof_counts))
            record = []
    assert not record
    return "".join(f"{line}\n" for line in result)


def _repair_lcov_record(
    record: list[str], prof_counts: dict[str, int]
) -> list[str]:
    fn_start_lines: dict[str, int] = {}
    mapped_counts: dict[str, int] = {}
    for line in record:
        if line.startswith("FN:"):
            start, _, name = line.removeprefix("FN:").partition(",")
            fn_start_lines[name] = int(start)
        elif line.startswith("FNDA:"):
            count, _, name = line.removeprefix("FNDA:").partition(",")
            mapped_counts[name] = max(mapped_counts.get(name, 0), int(count))

    repaired_lines: dict[int, int] = {}
    line_has_profiled_fn: dict[int, bool] = {}
    for fn_name, fn_start in fn_start_lines.items():
        if fn_name in prof_counts:
            line_has_profiled_fn[fn_start] = True
        else:
            line_has_profiled_fn.setdefault(fn_start, False)
        if mapped_counts.get(fn_name) == 0:
            true_count = prof_counts.get(fn_name, 0)
            if true_count > 0:
                repaired_lines[fn_start] = max(
                    repaired_lines.get(fn_start, 0), true_count
                )
    unmapped_lines = {
        start
        for start, profiled in line_has_profiled_fn.items()
        if not profiled
    }
    if not repaired_lines and not unmapped_lines:
        return record

    result = []
    for line in record:
        if line.startswith("DA:"):
            line_number, _, count = line.removeprefix("DA:").partition(",")
            if int(count) == 0:
                if int(line_number) in repaired_lines:
                    line = (
                        f"DA:{line_number},{repaired_lines[int(line_number)]}"
                    )
                elif int(line_number) in unmapped_lines:
                    continue
        result.append(line)
    return result


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
        prof_dump = session.run(
            str(target_bindir / ("llvm-profdata" + BIN_EXT)),
            "show",
            "--all-functions",
            "rust-cov.profdata",
            silent=True,
            external=True,
        )
        assert isinstance(prof_dump, str)
        lcov_data = _repair_expanded_code_coverage(
            lcov_data, _parse_profdata_function_counts(prof_dump)
        )
        with open(f"{uuid.uuid4()}.lcov", "w") as f:
            f.write(lcov_data)
