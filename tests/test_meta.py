# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import importlib.util
import os
import pkgutil
import subprocess
import sys

import pytest

import cryptography


def test_removed_cffi_binding():
    from cryptography.hazmat.bindings import _rust
    from cryptography.hazmat.bindings.openssl import binding

    # The former conditional CFFI module must not survive in built packages.
    assert (
        importlib.util.find_spec(
            "cryptography.hazmat.bindings.openssl._conditional"
        )
        is None
    )
    assert not hasattr(binding, "Binding")
    assert not hasattr(_rust, "_openssl")


def find_all_modules() -> list[str]:
    return sorted(
        mod
        for _, mod, _ in pkgutil.walk_packages(
            cryptography.__path__,
            prefix=cryptography.__name__ + ".",
        )
    )


@pytest.mark.parametrize("module", find_all_modules())
def test_no_circular_imports(module):
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(sys.path)

    argv = [sys.executable, "-c", f"__import__({module!r})"]
    subprocess.check_call(argv, env=env)
