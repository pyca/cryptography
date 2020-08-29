import textwrap
from io import StringIO
from itertools import chain
from typing import List, TextIO, Union

import isort.literal
from isort.settings import DEFAULT_CONFIG, Config

from . import output, parse
from .exceptions import FileSkipComment
from .format import format_natural, remove_whitespace
from .settings import FILE_SKIP_COMMENTS

CIMPORT_IDENTIFIERS = ("cimport ", "cimport*", "from.cimport")
IMPORT_START_IDENTIFIERS = ("from ", "from.import", "import ", "import*") + CIMPORT_IDENTIFIERS
COMMENT_INDICATORS = ('"""', "'''", "'", '"', "#")
CODE_SORT_COMMENTS = (
    "# isort: list",
    "# isort: dict",
    "# isort: set",
    "# isort: unique-list",
    "# isort: tuple",
    "# isort: unique-tuple",
    "# isort: assignments",
)


def process(
    input_stream: TextIO,
    output_stream: TextIO,
    extension: str = "py",
    config: Config = DEFAULT_CONFIG,
) -> bool:
    """Parses stream identifying sections of contiguous imports and sorting them

    Code with unsorted imports is read from the provided `input_stream`, sorted and then
    outputted to the specified `output_stream`.

    - `input_stream`: Text stream with unsorted import sections.
    - `output_stream`: Text stream to output sorted inputs into.
    - `config`: Config settings to use when sorting imports. Defaults settings.
        - *Default*: `isort.settings.DEFAULT_CONFIG`.
    - `extension`: The file extension or file extension rules that should be used.
        - *Default*: `"py"`.
        - *Choices*: `["py", "pyi", "pyx"]`.

    Returns `True` if there were changes that needed to be made (errors present) from what
    was provided in the input_stream, otherwise `False`.
    """
    line_separator: str = config.line_ending
    add_imports: List[str] = [format_natural(addition) for addition in config.add_imports]
    import_section: str = ""
    next_import_section: str = ""
    next_cimports: bool = False
    in_quote: str = ""
    first_comment_index_start: int = -1
    first_comment_index_end: int = -1
    contains_imports: bool = False
    in_top_comment: bool = False
    first_import_section: bool = True
    section_comments = [f"# {heading}" for heading in config.import_headings.values()]
    indent: str = ""
    isort_off: bool = False
    code_sorting: Union[bool, str] = False
    code_sorting_section: str = ""
    code_sorting_indent: str = ""
    cimports: bool = False
    made_changes: bool = False

    if config.float_to_top:
        new_input = ""
        current = ""
        isort_off = False
        for line in chain(input_stream, (None,)):
            if isort_off and line is not None:
                if line == "# isort: on\n":
                    isort_off = False
                new_input += line
            elif line in ("# isort: split\n", "# isort: off\n", None) or str(line).endswith(
                "# isort: split\n"
            ):
                if line == "# isort: off\n":
                    isort_off = True
                if current:
                    parsed = parse.file_contents(current, config=config)
                    extra_space = ""
                    while current[-1] == "\n":
                        extra_space += "\n"
                        current = current[:-1]
                    extra_space = extra_space.replace("\n", "", 1)
                    sorted_output = output.sorted_imports(
                        parsed, config, extension, import_type="import"
                    )
                    made_changes = made_changes or _has_changed(
                        before=current,
                        after=sorted_output,
                        line_separator=parsed.line_separator,
                        ignore_whitespace=config.ignore_whitespace,
                    )
                    new_input += sorted_output
                    new_input += extra_space
                    current = ""
                new_input += line or ""
            else:
                current += line or ""

        input_stream = StringIO(new_input)

    for index, line in enumerate(chain(input_stream, (None,))):
        if line is None:
            if index == 0 and not config.force_adds:
                return False

            not_imports = True
            line = ""
            if not line_separator:
                line_separator = "\n"

            if code_sorting and code_sorting_section:
                output_stream.write(
                    textwrap.indent(
                        isort.literal.assignment(
                            code_sorting_section,
                            str(code_sorting),
                            extension,
                            config=_indented_config(config, indent),
                        ),
                        code_sorting_indent,
                    )
                )
        else:
            stripped_line = line.strip()
            if stripped_line and not line_separator:
                line_separator = line[len(line.rstrip()) :].replace(" ", "").replace("\t", "")

            for file_skip_comment in FILE_SKIP_COMMENTS:
                if file_skip_comment in line:
                    raise FileSkipComment("Passed in content")

            if (
                (index == 0 or (index in (1, 2) and not contains_imports))
                and stripped_line.startswith("#")
                and stripped_line not in section_comments
            ):
                in_top_comment = True
            elif in_top_comment:
                if not line.startswith("#") or stripped_line in section_comments:
                    in_top_comment = False
                    first_comment_index_end = index - 1

            if (not stripped_line.startswith("#") or in_quote) and '"' in line or "'" in line:
                char_index = 0
                if first_comment_index_start == -1 and (
                    line.startswith('"') or line.startswith("'")
                ):
                    first_comment_index_start = index
                while char_index < len(line):
                    if line[char_index] == "\\":
                        char_index += 1
                    elif in_quote:
                        if line[char_index : char_index + len(in_quote)] == in_quote:
                            in_quote = ""
                            if first_comment_index_end < first_comment_index_start:
                                first_comment_index_end = index
                    elif line[char_index] in ("'", '"'):
                        long_quote = line[char_index : char_index + 3]
                        if long_quote in ('"""', "'''"):
                            in_quote = long_quote
                            char_index += 2
                        else:
                            in_quote = line[char_index]
                    elif line[char_index] == "#":
                        break
                    char_index += 1

            not_imports = bool(in_quote) or in_top_comment or isort_off
            if not (in_quote or in_top_comment):
                stripped_line = line.strip()
                if isort_off:
                    if stripped_line == "# isort: on":
                        isort_off = False
                elif stripped_line == "# isort: off":
                    not_imports = True
                    isort_off = True
                elif stripped_line.endswith("# isort: split"):
                    not_imports = True
                elif stripped_line in CODE_SORT_COMMENTS:
                    code_sorting = stripped_line.split("isort: ")[1].strip()
                    code_sorting_indent = line[: -len(line.lstrip())]
                    not_imports = True
                elif code_sorting:
                    if not stripped_line:
                        output_stream.write(
                            textwrap.indent(
                                isort.literal.assignment(
                                    code_sorting_section,
                                    str(code_sorting),
                                    extension,
                                    config=_indented_config(config, indent),
                                ),
                                code_sorting_indent,
                            )
                        )
                        not_imports = True
                        code_sorting = False
                        code_sorting_section = ""
                        code_sorting_indent = ""
                    else:
                        code_sorting_section += line
                        line = ""
                elif stripped_line in config.section_comments and not import_section:
                    import_section += line
                    indent = line[: -len(line.lstrip())]
                elif not (stripped_line or contains_imports):
                    if add_imports and not indent and not config.append_only:
                        if not import_section:
                            output_stream.write(line)
                            line = ""
                        import_section += line_separator.join(add_imports) + line_separator
                        contains_imports = True
                        add_imports = []
                    else:
                        not_imports = True
                elif (
                    not stripped_line
                    or stripped_line.startswith("#")
                    and (not indent or indent + line.lstrip() == line)
                    and not config.treat_all_comments_as_code
                    and stripped_line not in config.treat_comments_as_code
                ):
                    import_section += line
                elif stripped_line.startswith(IMPORT_START_IDENTIFIERS):
                    contains_imports = True

                    new_indent = line[: -len(line.lstrip())]
                    import_statement = line
                    stripped_line = line.strip().split("#")[0]
                    while stripped_line.endswith("\\") or (
                        "(" in stripped_line and ")" not in stripped_line
                    ):
                        if stripped_line.endswith("\\"):
                            while stripped_line and stripped_line.endswith("\\"):
                                line = input_stream.readline()
                                stripped_line = line.strip().split("#")[0]
                                import_statement += line
                        else:
                            while ")" not in stripped_line:
                                line = input_stream.readline()
                                stripped_line = line.strip().split("#")[0]
                                import_statement += line

                    cimport_statement: bool = False
                    if (
                        import_statement.lstrip().startswith(CIMPORT_IDENTIFIERS)
                        or " cimport " in import_statement
                        or " cimport*" in import_statement
                        or " cimport(" in import_statement
                        or ".cimport" in import_statement
                    ):
                        cimport_statement = True

                    if cimport_statement != cimports or (new_indent != indent and import_section):
                        if import_section:
                            next_cimports = cimport_statement
                            next_import_section = import_statement
                            import_statement = ""
                            not_imports = True
                            line = ""
                        else:
                            cimports = cimport_statement

                    indent = new_indent
                    import_section += import_statement
                else:
                    not_imports = True

        if not_imports:
            raw_import_section: str = import_section
            if (
                add_imports
                and not config.append_only
                and not in_top_comment
                and not in_quote
                and not import_section
                and not line.lstrip().startswith(COMMENT_INDICATORS)
            ):
                import_section = line_separator.join(add_imports) + line_separator
                contains_imports = True
                add_imports = []

            if next_import_section and not import_section:  # pragma: no cover
                raw_import_section = import_section = next_import_section
                next_import_section = ""

            if import_section:
                if add_imports and not indent:
                    import_section = (
                        line_separator.join(add_imports) + line_separator + import_section
                    )
                    contains_imports = True
                    add_imports = []

                if not indent:
                    import_section += line
                    raw_import_section += line
                if not contains_imports:
                    output_stream.write(import_section)
                else:
                    leading_whitespace = import_section[: -len(import_section.lstrip())]
                    trailing_whitespace = import_section[len(import_section.rstrip()) :]
                    if first_import_section and not import_section.lstrip(
                        line_separator
                    ).startswith(COMMENT_INDICATORS):
                        import_section = import_section.lstrip(line_separator)
                        raw_import_section = raw_import_section.lstrip(line_separator)
                        first_import_section = False

                    if indent:
                        import_section = "".join(
                            line[len(indent) :] for line in import_section.splitlines(keepends=True)
                        )

                    sorted_import_section = output.sorted_imports(
                        parse.file_contents(import_section, config=config),
                        _indented_config(config, indent),
                        extension,
                        import_type="cimport" if cimports else "import",
                    )
                    if not (import_section.strip() and not sorted_import_section):
                        if indent:
                            sorted_import_section = (
                                leading_whitespace
                                + textwrap.indent(sorted_import_section, indent).strip()
                                + trailing_whitespace
                            )

                        made_changes = made_changes or _has_changed(
                            before=raw_import_section,
                            after=sorted_import_section,
                            line_separator=line_separator,
                            ignore_whitespace=config.ignore_whitespace,
                        )

                        output_stream.write(sorted_import_section)
                        if not line and not indent and next_import_section:
                            output_stream.write(line_separator)

                if indent:
                    output_stream.write(line)
                    if not next_import_section:
                        indent = ""

                if next_import_section:
                    cimports = next_cimports
                    contains_imports = True
                else:
                    contains_imports = False
                import_section = next_import_section
                next_import_section = ""
            else:
                output_stream.write(line)
                not_imports = False

    return made_changes


def _indented_config(config: Config, indent: str):
    if not indent:
        return config

    return Config(
        config=config,
        line_length=max(config.line_length - len(indent), 0),
        wrap_length=max(config.wrap_length - len(indent), 0),
        lines_after_imports=1,
    )


def _has_changed(before: str, after: str, line_separator: str, ignore_whitespace: bool) -> bool:
    if ignore_whitespace:
        return (
            remove_whitespace(before, line_separator=line_separator).strip()
            != remove_whitespace(after, line_separator=line_separator).strip()
        )
    else:
        return before.strip() != after.strip()
