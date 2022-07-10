# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import json
import sys


def bench_data_as_dict(data):
    return {d["fullname"]: d["stats"] for d in data["benchmarks"]}


def main(base_bench_path, pr_bench_path):
    with open(base_bench_path) as f:
        base_bench_data = bench_data_as_dict(json.load(f))
    with open(pr_bench_path) as f:
        pr_bench_data = bench_data_as_dict(json.load(f))

    print("| Benchmark | Base | PR | Delta |")
    print("| --------- | ---- | -- | ----- |")
    for bench_name in sorted(base_bench_data):
        # TODO: use better statistics than just comparing medians
        base_result = base_bench_data[bench_name]["median"]
        pr_result = pr_bench_data[bench_name]["median"]

        if base_result == pr_result:
            # PR and base are identical
            delta = "--"
        elif base_result > pr_result:
            # PR is faster than base
            delta = f"{100 - round(100 * pr_result / base_result)}% faster"
        else:
            delta = f"{100 - round(100 * base_result / pr_result)}% slower"

        print(
            f"| `{bench_name}` | {round(base_result * 1000 * 1000 * 1000, 2)} "
            f"ns | {round(pr_result * 1000 * 1000 * 1000, 2)} ns | {delta} |"
        )


if __name__ == "__main__":
    main(*sys.argv[1:])
