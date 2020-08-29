# Licensed under the GPL: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
# For details: https://github.com/PyCQA/pylint/blob/master/COPYING

import contextlib
import sys

from pylint.utils import utils


class ArgumentPreprocessingError(Exception):
    """Raised if an error occurs during argument preprocessing."""


def preprocess_options(args, search_for):
    """look for some options (keys of <search_for>) which have to be processed
    before others

    values of <search_for> are callback functions to call when the option is
    found
    """
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("--"):
            try:
                option, val = arg[2:].split("=", 1)
            except ValueError:
                option, val = arg[2:], None
            try:
                cb, takearg = search_for[option]
            except KeyError:
                i += 1
            else:
                del args[i]
                if takearg and val is None:
                    if i >= len(args) or args[i].startswith("-"):
                        msg = "Option %s expects a value" % option
                        raise ArgumentPreprocessingError(msg)
                    val = args[i]
                    del args[i]
                elif not takearg and val is not None:
                    msg = "Option %s doesn't expects a value" % option
                    raise ArgumentPreprocessingError(msg)
                cb(option, val)
        else:
            i += 1


def _patch_sys_path(args):
    original = list(sys.path)
    changes = []
    seen = set()
    for arg in args:
        path = utils.get_python_path(arg)
        if path not in seen:
            changes.append(path)
            seen.add(path)

    sys.path[:] = changes + sys.path
    return original


@contextlib.contextmanager
def fix_import_path(args):
    """Prepare sys.path for running the linter checks.

    Within this context, each of the given arguments is importable.
    Paths are added to sys.path in corresponding order to the arguments.
    We avoid adding duplicate directories to sys.path.
    `sys.path` is reset to its original value upon exiting this context.
    """
    original = _patch_sys_path(args)
    try:
        yield
    finally:
        sys.path[:] = original
