#!/usr/bin/env python

# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import os
import platform
import re
import shutil
import subprocess
import sys
import warnings

from setuptools import setup

try:
    from setuptools_rust import RustExtension
except ImportError:
    print(
        """
        =============================DEBUG ASSISTANCE==========================
        If you are seeing an error here please try the following to
        successfully install cryptography:

        Upgrade to the latest pip and try again. This will fix errors for most
        users. See: https://pip.pypa.io/en/stable/installing/#upgrading-pip
        =============================DEBUG ASSISTANCE==========================
        """
    )
    raise


# distutils emits this warning if you pass `setup()` an unknown option. This
# is what happens if you somehow run this file without `cffi` installed:
# `cffi_modules` is an unknown option.
warnings.filterwarnings("error", message="Unknown distribution option")

base_dir = os.path.dirname(__file__)
src_dir = os.path.join(base_dir, "src")

# When executing the setup.py, we need to be able to import ourselves, this
# means that we need to add the src/ directory to the sys.path.
sys.path.insert(0, src_dir)

if hasattr(sys, "pypy_version_info") and sys.pypy_version_info < (7, 3, 10):
    raise RuntimeError("cryptography is not compatible with PyPy3 < 7.3.10")

try:
    # See pyproject.toml for most of the config metadata.
    setup(
        rust_extensions=[
            RustExtension(
                "cryptography.hazmat.bindings._rust",
                "src/rust/Cargo.toml",
                py_limited_api=True,
                rust_version=">=1.56.0",
            )
        ],
    )
except:  # noqa: E722
    # Note: This is a bare exception that re-raises so that we don't interfere
    # with anything the installation machinery might want to do. Because we
    # print this for any exception this msg can appear (e.g. in verbose logs)
    # even if there's no failure. For example, SetupRequirementsError is raised
    # during PEP517 building and prints this text. setuptools raises SystemExit
    # when compilation fails right now, but it's possible this isn't stable
    # or a public API commitment so we'll remain ultra conservative.

    import pkg_resources

    print(
        """
    =============================DEBUG ASSISTANCE=============================
    If you are seeing a compilation error please try the following steps to
    successfully install cryptography:
    1) Upgrade to the latest pip and try again. This will fix errors for most
       users. See: https://pip.pypa.io/en/stable/installing/#upgrading-pip
    2) Read https://cryptography.io/en/latest/installation/ for specific
       instructions for your platform.
    3) Check our frequently asked questions for more information:
       https://cryptography.io/en/latest/faq/
    4) Ensure you have a recent Rust toolchain installed:
       https://cryptography.io/en/latest/installation/#rust
    """
    )
    print(f"    Python: {'.'.join(str(v) for v in sys.version_info[:3])}")
    print(f"    platform: {platform.platform()}")
    for dist in ["pip", "setuptools", "setuptools_rust"]:
        try:
            version = pkg_resources.get_distribution(dist).version
        except pkg_resources.DistributionNotFound:
            version = "n/a"
        print(f"    {dist}: {version}")
    version = "n/a"
    if shutil.which("rustc") is not None:
        try:
            # If for any reason `rustc --version` fails, silently ignore it
            rustc_output = subprocess.run(
                ["rustc", "--version"],
                capture_output=True,
                timeout=0.5,
                encoding="utf8",
                check=True,
            ).stdout
            version = re.sub("^rustc ", "", rustc_output.strip())
        except subprocess.SubprocessError:
            pass
    print(f"    rustc: {version}")

    print(
        """\
    =============================DEBUG ASSISTANCE=============================
    """
    )
    raise
