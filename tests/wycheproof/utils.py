# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import json


def load_tests(wycheproof, test_file):
    path = os.path.join(wycheproof, "testvectors", test_file)
    with open(path) as f:
        data = json.load(f)
        for group in data["testGroups"]:
            cases = group.pop("tests")
            for c in cases:
                yield group, c
