import os
import sys
from contextlib import contextmanager
from typing import Iterator


def exists_case_sensitive(path: str) -> bool:
    """Returns if the given path exists and also matches the case on Windows.

    When finding files that can be imported, it is important for the cases to match because while
    file os.path.exists("module.py") and os.path.exists("MODULE.py") both return True on Windows,
    Python can only import using the case of the real file.
    """
    result = os.path.exists(path)
    if (sys.platform.startswith("win") or sys.platform == "darwin") and result:  # pragma: no cover
        directory, basename = os.path.split(path)
        result = basename in os.listdir(directory)
    return result


@contextmanager
def chdir(path: str) -> Iterator[None]:
    """Context manager for changing dir and restoring previous workdir after exit."""
    curdir = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(curdir)
