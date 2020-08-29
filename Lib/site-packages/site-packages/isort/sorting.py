import re
from typing import Any, Callable, Iterable, List, Optional

from .settings import Config

_import_line_intro_re = re.compile("^(?:from|import) ")
_import_line_midline_import_re = re.compile(" import ")


def module_key(
    module_name: str,
    config: Config,
    sub_imports: bool = False,
    ignore_case: bool = False,
    section_name: Optional[Any] = None,
    straight_import: Optional[bool] = False,
) -> str:
    match = re.match(r"^(\.+)\s*(.*)", module_name)
    if match:
        sep = " " if config.reverse_relative else "_"
        module_name = sep.join(match.groups())

    prefix = ""
    if ignore_case:
        module_name = str(module_name).lower()
    else:
        module_name = str(module_name)

    if sub_imports and config.order_by_type:
        if module_name in config.constants:
            prefix = "A"
        elif module_name in config.classes:
            prefix = "B"
        elif module_name in config.variables:
            prefix = "C"
        elif module_name.isupper() and len(module_name) > 1:  # see issue #376
            prefix = "A"
        elif module_name in config.classes or module_name[0:1].isupper():
            prefix = "B"
        else:
            prefix = "C"
    if not config.case_sensitive:
        module_name = module_name.lower()

    length_sort = (
        config.length_sort
        or (config.length_sort_straight and straight_import)
        or str(section_name).lower() in config.length_sort_sections
    )
    _length_sort_maybe = length_sort and (str(len(module_name)) + ":" + module_name) or module_name
    return f"{module_name in config.force_to_top and 'A' or 'B'}{prefix}{_length_sort_maybe}"


def section_key(
    line: str,
    order_by_type: bool,
    force_to_top: List[str],
    lexicographical: bool = False,
    length_sort: bool = False,
) -> str:
    section = "B"

    if lexicographical:
        line = _import_line_intro_re.sub("", _import_line_midline_import_re.sub(".", line))
    else:
        line = re.sub("^from ", "", line)
        line = re.sub("^import ", "", line)
    if line.split(" ")[0] in force_to_top:
        section = "A"
    if not order_by_type:
        line = line.lower()

    return f"{section}{len(line) if length_sort else ''}{line}"


def naturally(to_sort: Iterable[str], key: Optional[Callable[[str], Any]] = None) -> List[str]:
    """Returns a naturally sorted list"""
    if key is None:
        key_callback = _natural_keys
    else:

        def key_callback(text: str) -> List[Any]:
            return _natural_keys(key(text))  # type: ignore

    return sorted(to_sort, key=key_callback)


def _atoi(text: str) -> Any:
    return int(text) if text.isdigit() else text


def _natural_keys(text: str) -> List[Any]:
    return [_atoi(c) for c in re.split(r"(\d+)", text)]
