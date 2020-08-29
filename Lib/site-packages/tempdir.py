import os
import tempfile
import shutil
from functools import wraps
from contextlib import contextmanager

class TempDir(object):
    """ class for temporary directories
creates a (named) directory which is deleted after use.
All files created within the directory are destroyed
Might not work on windows when the files are still opened
"""
    def __init__(self, suffix="", prefix="tmp", basedir=None):
        self.name = tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=basedir)

    def __del__(self):
        try:
            if self.name:
                self.dissolve()
        except AttributeError:
            pass

    def __enter__(self):
        return self.name

    def __exit__(self, *errstuff):
        self.dissolve()

    def dissolve(self):
        """remove all files and directories created within the tempdir"""
        if self.name:
            shutil.rmtree(self.name)
        self.name = ""

    def __str__(self):
        if self.name:
            return "temporary directory at: %s" % (self.name,)
        else:
            return "dissolved temporary directory"


class in_tempdir(object):
    """Create a temporary directory and change to it.  """

    def __init__(self, *args, **kwargs):
        self.tmpdir = TempDir(*args, **kwargs)

    def __enter__(self):
        self.old_path = os.getcwd()
        os.chdir(self.tmpdir.name)
        return self.tmpdir.name

    def __exit__(self, *errstuff):
        os.chdir(self.old_path)
        self.tmpdir.dissolve()

def run_in_tempdir(*args, **kwargs):
    """Make a function execute in a new tempdir.
    Any time the function is called, a new tempdir is created and destroyed.
    """
    def change_dird(fnc):
        @wraps(fnc)
        def wrapper(*funcargs, **funckwargs):
            with in_tempdir(*args, **kwargs):
                return fnc(*funcargs, **funckwargs)
        return wrapper
    return change_dird


