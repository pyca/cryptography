# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

# break import cycle, see https://github.com/pyca/cryptography/issues/5794
from . import serialization
