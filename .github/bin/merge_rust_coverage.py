# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import collections.abc
import sys

import coverage


class RustCoveragePlugin(coverage.CoveragePlugin):
    def __init__(
        self,
        coverage_data: collections.abc.Mapping[
            str, collections.abc.Mapping[int, int]
        ],
    ) -> None:
        super().__init__()
        self._data = coverage_data

    def file_reporter(self, filename: str) -> coverage.FileReporter:
        return RustCoverageFileReporter(filename, self._data[filename])


class RustCoverageFileReporter(coverage.FileReporter):
    def __init__(
        self, filename: str, coverage_data: collections.abc.Mapping[int, int]
    ) -> None:
        super().__init__(filename)
        self._data = coverage_data

    def lines(self) -> set[int]:
        return set(self._data)

    def arcs(self) -> set[tuple[int, int]]:
        return {(-1, line) for line in self._data}


def main(*lcov_paths: str):
    coverage_data = coverage.CoverageData(suffix="rust")

    # {filename: {line_number: count}}
    raw_data = collections.defaultdict(lambda: collections.defaultdict(int))
    current_file = None
    for p in lcov_paths:
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line == "end_of_record":
                    assert current_file is not None
                    current_file = None
                    continue

                prefix, suffix = line.split(":", 1)
                match prefix:
                    case "SF":
                        current_file = raw_data[suffix]
                    case "DA":
                        assert current_file is not None
                        line_number, count = suffix.split(",")
                        current_file[int(line_number)] += int(count)
                    case (
                        "BRF"
                        | "BRH"
                        | "FN"
                        | "FNDA"
                        | "FNF"
                        | "FNH"
                        | "LF"
                        | "LH"
                    ):
                        # These are various forms of metadata and summary stats
                        # that we don't need.
                        pass
                    case _:
                        raise NotImplementedError(prefix)

    covered_lines = {
        file_name: {(-1, line) for line, c in lines.items() if c > 0}
        for file_name, lines in raw_data.items()
    }
    coverage_data.add_arcs(covered_lines)
    coverage_data.add_file_tracers(
        dict.fromkeys(covered_lines, "None.RustCoveragePlugin")
    )
    coverage_data.write()

    cov = coverage.Coverage(
        plugins=[lambda reg: reg.add_file_tracer(RustCoveragePlugin(raw_data))]
    )
    cov.combine()
    coverage_percent = cov.report(show_missing=True)
    if coverage_percent < 100:
        print("+++ Combined coverage under 100% +++")
        cov.html_report()
        sys.exit(1)


if __name__ == "__main__":
    main(*sys.argv[1:])
