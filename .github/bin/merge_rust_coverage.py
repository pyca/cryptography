# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import collections
import sys

import coverage


class RustCoveragePlugin(coverage.CoveragePlugin):
    def file_reporter(self, filename: str):
        return RustCoverageFileReporter(filename)


class RustCoverageFileReporter(coverage.FileReporter):
    def lines(self) -> set[int]:
        # XXX: Need a better way to handle this state!
        return set(raw_data[self.filename])

    def arcs(self) -> set[tuple[int, int]]:
        return {(-1, line) for line in self.lines()}


def coverage_init(
    reg: coverage.plugin_support.Plugins,
    options: coverage.types.TConfigSectionOut,
) -> None:
    reg.add_file_tracer(RustCoveragePlugin())


def main(*lcov_paths: str):
    cov = coverage.Coverage()
    # XXX: Nasty mucking in semi-public APIs
    cov.config.plugins.append("coverage_rust_plugin")
    sys.modules["coverage_rust_plugin"] = sys.modules[__name__]

    coverage_data = coverage.CoverageData(suffix="rust")

    # XXX: global state! Bad!
    global raw_data
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
        {
            file_name: "coverage_rust_plugin.RustCoveragePlugin"
            for file_name in covered_lines
        }
    )
    coverage_data.write()

    cov.combine()
    coverage_percent = cov.report(show_missing=True)
    if coverage_percent < 100:
        print("+++ Combined coverage under 100% +++")
        cov.html_report()
        sys.exit(1)


if __name__ == "__main__":
    main(*sys.argv[1:])
