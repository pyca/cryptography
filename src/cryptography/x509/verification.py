# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.bindings._rust import x509 as rust_x509

__all__ = ["Store"]

Store = rust_x509.Store
