# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import pathlib
import runpy
import sys

import pytest

_SCRIPT = (
    pathlib.Path(__file__).resolve().parent.parent
    / ".github/bin/merge_rust_coverage.py"
)
pytestmark = pytest.mark.skipif(
    not _SCRIPT.exists() or sys.version_info < (3, 10),
    reason="Coverage CI tooling requires a checkout and Python 3.10+",
)


@pytest.fixture(scope="module")
def coverage_tool():
    return runpy.run_path(str(_SCRIPT))


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("fn covered() {}\n", []),
        (
            "fn before() {}\n"
            "    // NO-COVERAGE-START\n"
            "    // Unicode explanation: μ.\n"
            "    unreachable!();\n"
            "    // NO-COVERAGE-END\n"
            "fn after() {}\n",
            [2, 3, 4, 5],
        ),
        (
            "// NO-COVERAGE-START\n// NO-COVERAGE-END\n"
            "fn covered() {}\n"
            "// NO-COVERAGE-START\nreturn Err(error);\n"
            "// NO-COVERAGE-END\n",
            [1, 2, 4, 5, 6],
        ),
    ],
)
def test_exclusion_boundaries(coverage_tool, tmp_path, source, expected):
    path = tmp_path / "source.rs"
    path.write_text(source, encoding="utf-8")
    assert coverage_tool["get_excluded_lines"](str(path)) == expected


@pytest.mark.parametrize(
    "source",
    [
        "// NO-COVERAGE-START\n",
        "// NO-COVERAGE-END\n",
        "// NO-COVERAGE-START\n// NO-COVERAGE-START\n",
        "fn covered() {} // NO-COVERAGE-START\n",
        "// NO-COVERAGE-START\nreturn Err(error); // NO-COVERAGE-END\n",
    ],
)
def test_malformed_exclusions_fail_closed(coverage_tool, tmp_path, source):
    path = tmp_path / "source.rs"
    path.write_text(source, encoding="utf-8")
    with pytest.raises(ValueError):
        coverage_tool["get_excluded_lines"](str(path))


def test_repository_exclusions_are_well_formed(coverage_tool):
    paths = list((_SCRIPT.parents[2] / "src/rust").rglob("*.rs"))
    assert paths
    for path in paths:
        coverage_tool["get_excluded_lines"](str(path))
