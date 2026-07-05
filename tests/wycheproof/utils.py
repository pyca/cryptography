# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

import pytest

from ..utils import load_wycheproof_tests


def wycheproof_tests(*paths, subdir="testvectors_v1"):
    # Each entry in paths is either a filename, or a (filename, num_shards)
    # tuple. Sharded files are split into num_shards separate test items so
    # that expensive vector files don't serialize on a single xdist worker.
    params: list[typing.Any] = []
    for entry in paths:
        if isinstance(entry, tuple):
            path, num_shards = entry
            params.extend(
                pytest.param(path, shard, num_shards, id=f"{path}-{shard}")
                for shard in range(num_shards)
            )
        else:
            params.append(pytest.param(entry, 0, 1, id=entry))

    def wrapper(func):
        @pytest.mark.parametrize(("path", "shard", "num_shards"), params)
        def run_wycheproof(
            backend, subtests, pytestconfig, path, shard, num_shards
        ):
            wycheproof_root = pytestconfig.getoption(
                "--wycheproof-root", skip=True
            )
            tests = load_wycheproof_tests(wycheproof_root, path, subdir)
            for i, test in enumerate(tests):
                if i % num_shards != shard:
                    continue
                with subtests.test():
                    func(backend, test)

        return run_wycheproof

    return wrapper
