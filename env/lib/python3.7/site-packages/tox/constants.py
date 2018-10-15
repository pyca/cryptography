"""All non private names (no leading underscore) here are part of the tox API.

They live in the tox namespace and can be accessed as tox.[NAMESPACE.]NAME
"""
import re
import sys


def _construct_default_factors(cpython_versions, pypy_versions, other_interpreters):
    default_factors = {"py": sys.executable, "py2": "python2", "py3": "python3"}
    default_factors.update(
        {
            "py{}{}".format(major, minor): "python{}.{}".format(major, minor)
            for major, minor in cpython_versions
        }
    )
    default_factors.update({exc: exc for exc in ["pypy", "pypy2", "pypy3"]})
    default_factors.update(
        {
            "pypy{}{}".format(major, minor): "pypy{}.{}".format(major, minor)
            for major, minor in pypy_versions
        }
    )
    default_factors.update({interpreter: interpreter for interpreter in other_interpreters})
    return default_factors


class PYTHON:
    PY_FACTORS_RE = re.compile("^(?!py$)(py|pypy|jython)([2-9][0-9]?)?$")
    PY_FACTORS_MAP = {"py": "python", "pypy": "pypy", "jython": "jython"}
    CPYTHON_VERSION_TUPLES = [(2, 7), (3, 4), (3, 5), (3, 6), (3, 7), (3, 8)]
    PYPY_VERSION_TUPLES = [(2, 7), (3, 5)]
    OTHER_PYTHON_INTERPRETERS = ["jython"]
    DEFAULT_FACTORS = _construct_default_factors(
        CPYTHON_VERSION_TUPLES, PYPY_VERSION_TUPLES, OTHER_PYTHON_INTERPRETERS
    )
    CURRENT_RELEASE_ENV = "py36"
    """Should hold currently released py -> for easy updating"""
    QUICKSTART_PY_ENVS = ["py27", "py34", "py35", CURRENT_RELEASE_ENV, "pypy", "jython"]
    """For choices in tox-quickstart"""


class INFO:
    DEFAULT_CONFIG_NAME = "tox.ini"
    CONFIG_CANDIDATES = ("pyproject.toml", "tox.ini", "setup.cfg")
    IS_WIN = sys.platform == "win32"


class PIP:
    SHORT_OPTIONS = ["c", "e", "r", "b", "t", "d"]
    LONG_OPTIONS = [
        "build",
        "cache-dir",
        "client-cert",
        "constraint",
        "download",
        "editable",
        "exists-action",
        "extra-index-url",
        "global-option",
        "find-links",
        "index-url",
        "install-options",
        "prefix",
        "proxy",
        "no-binary",
        "only-binary",
        "requirement",
        "retries",
        "root",
        "src",
        "target",
        "timeout",
        "trusted-host",
        "upgrade-strategy",
    ]
    INSTALL_SHORT_OPTIONS_ARGUMENT = ["-{}".format(option) for option in SHORT_OPTIONS]
    INSTALL_LONG_OPTIONS_ARGUMENT = ["--{}".format(option) for option in LONG_OPTIONS]
