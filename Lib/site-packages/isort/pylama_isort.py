import os
import sys
from contextlib import contextmanager
from typing import Any, Dict, List

from pylama.lint import Linter as BaseLinter

from . import api


@contextmanager
def supress_stdout():
    stdout = sys.stdout
    with open(os.devnull, "w") as devnull:
        sys.stdout = devnull
        yield
        sys.stdout = stdout


class Linter(BaseLinter):
    def allow(self, path: str) -> bool:
        """Determine if this path should be linted."""
        return path.endswith(".py")

    def run(self, path: str, **meta: Any) -> List[Dict[str, Any]]:
        """Lint the file. Return an array of error dicts if appropriate."""
        with supress_stdout():
            if not api.check_file(path):
                return [
                    {"lnum": 0, "col": 0, "text": "Incorrectly sorted imports.", "type": "ISORT"}
                ]
            else:
                return []
