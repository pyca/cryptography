"""Wrapper for maturin to control --features flag for PEP 517 builds.

Remove this once maturin supports features=pyo3/abi3-auto
https://github.com/PyO3/maturin/issues/1894#issuecomment-2852639577
"""

import os
import sys

from maturin import *  # Import everything from maturin  # noqa: F403

# Latest supported Python version is 3.13
MAJOR, MINOR = sys.version_info.major, min(sys.version_info.minor, 13)

current_args = os.environ.get("MATURIN_PEP517_ARGS", "")
if "--features" not in current_args:
    # Add ABI3 feature flag for current Python version to use limited ABI3 for
    # compatibility, since maturin can't set this automatically
    features_arg = f" --features=pyo3/abi3-py{MAJOR}{MINOR}"
    os.environ["MATURIN_PEP517_ARGS"] = current_args + features_arg
