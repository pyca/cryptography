import sys
from datetime import datetime
from difflib import unified_diff
from pathlib import Path
from typing import Optional, TextIO

try:
    import colorama
except ImportError:
    colorama_unavailable = True
else:
    colorama_unavailable = False
    colorama.init()


def format_simplified(import_line: str) -> str:
    import_line = import_line.strip()
    if import_line.startswith("from "):
        import_line = import_line.replace("from ", "")
        import_line = import_line.replace(" import ", ".")
    elif import_line.startswith("import "):
        import_line = import_line.replace("import ", "")

    return import_line


def format_natural(import_line: str) -> str:
    import_line = import_line.strip()
    if not import_line.startswith("from ") and not import_line.startswith("import "):
        if "." not in import_line:
            return f"import {import_line}"
        parts = import_line.split(".")
        end = parts.pop(-1)
        return f"from {'.'.join(parts)} import {end}"

    return import_line


def show_unified_diff(
    *, file_input: str, file_output: str, file_path: Optional[Path], output: Optional[TextIO] = None
):
    """Shows a unified_diff for the provided input and output against the provided file path.

    - **file_input**: A string that represents the contents of a file before changes.
    - **file_output**: A string that represents the contents of a file after changes.
    - **file_path**: A Path object that represents the file path of the file being changed.
    - **output**: A stream to output the diff to. If non is provided uses sys.stdout.
    """
    output = sys.stdout if output is None else output
    file_name = "" if file_path is None else str(file_path)
    file_mtime = str(
        datetime.now() if file_path is None else datetime.fromtimestamp(file_path.stat().st_mtime)
    )
    unified_diff_lines = unified_diff(
        file_input.splitlines(keepends=True),
        file_output.splitlines(keepends=True),
        fromfile=file_name + ":before",
        tofile=file_name + ":after",
        fromfiledate=file_mtime,
        tofiledate=str(datetime.now()),
    )
    for line in unified_diff_lines:
        output.write(line)


def ask_whether_to_apply_changes_to_file(file_path: str) -> bool:
    answer = None
    while answer not in ("yes", "y", "no", "n", "quit", "q"):
        answer = input(f"Apply suggested changes to '{file_path}' [y/n/q]? ")  # nosec
        answer = answer.lower()
        if answer in ("no", "n"):
            return False
        if answer in ("quit", "q"):
            sys.exit(1)
    return True


def remove_whitespace(content: str, line_separator: str = "\n") -> str:
    content = content.replace(line_separator, "").replace(" ", "").replace("\x0c", "")
    return content


class BasicPrinter:
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"

    def success(self, message: str) -> None:
        print(f"{self.SUCCESS}: {message}")

    def error(self, message: str) -> None:
        print(
            f"{self.ERROR}: {message}",
            # TODO this should print to stderr, but don't want to make it backward incompatible now
            # file=sys.stderr
        )


class ColoramaPrinter(BasicPrinter):
    def __init__(self):
        self.ERROR = self.style_text("ERROR", colorama.Fore.RED)
        self.SUCCESS = self.style_text("SUCCESS", colorama.Fore.GREEN)

    @staticmethod
    def style_text(text: str, style: str) -> str:
        return style + text + colorama.Style.RESET_ALL


def create_terminal_printer(color: bool):
    if color and colorama_unavailable:
        no_colorama_message = (
            "\n"
            "Sorry, but to use --color (color_output) the colorama python package is required.\n\n"
            "Reference: https://pypi.org/project/colorama/\n\n"
            "You can either install it separately on your system or as the colors extra "
            "for isort. Ex: \n\n"
            "$ pip install isort[colors]\n"
        )
        print(no_colorama_message, file=sys.stderr)
        sys.exit(1)

    return ColoramaPrinter() if color else BasicPrinter()
