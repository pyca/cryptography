"""Tool for sorting imports alphabetically, and automatically separated into sections."""
import argparse
import functools
import json
import os
import sys
from io import TextIOWrapper
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set
from warnings import warn

from . import __version__, api, sections
from .exceptions import FileSkipped
from .logo import ASCII_ART
from .profiles import profiles
from .settings import VALID_PY_TARGETS, Config, WrapModes

try:
    from .setuptools_commands import ISortCommand  # noqa: F401
except ImportError:
    pass

DEPRECATED_SINGLE_DASH_ARGS = {
    "-ac",
    "-af",
    "-ca",
    "-cs",
    "-df",
    "-ds",
    "-dt",
    "-fas",
    "-fass",
    "-ff",
    "-fgw",
    "-fss",
    "-lai",
    "-lbt",
    "-le",
    "-ls",
    "-nis",
    "-nlb",
    "-ot",
    "-rr",
    "-sd",
    "-sg",
    "-sl",
    "-sp",
    "-tc",
    "-wl",
    "-ws",
}
QUICK_GUIDE = f"""
{ASCII_ART}

Nothing to do: no files or paths have have been passed in!

Try one of the following:

    `isort .` - sort all Python files, starting from the current directory, recursively.
    `isort . --interactive` - Do the same, but ask before making any changes.
    `isort . --check --diff` - Check to see if imports are correctly sorted within this project.
    `isort --help` - In-depth information about isort's available command-line options.

Visit https://timothycrosley.github.io/isort/ for complete information about how to use isort.
"""


class SortAttempt:
    def __init__(self, incorrectly_sorted: bool, skipped: bool) -> None:
        self.incorrectly_sorted = incorrectly_sorted
        self.skipped = skipped


def sort_imports(
    file_name: str,
    config: Config,
    check: bool = False,
    ask_to_apply: bool = False,
    write_to_stdout: bool = False,
    **kwargs: Any,
) -> Optional[SortAttempt]:
    try:
        incorrectly_sorted: bool = False
        skipped: bool = False
        if check:
            try:
                incorrectly_sorted = not api.check_file(file_name, config=config, **kwargs)
            except FileSkipped:
                skipped = True
            return SortAttempt(incorrectly_sorted, skipped)
        else:
            try:
                incorrectly_sorted = not api.sort_file(
                    file_name,
                    config=config,
                    ask_to_apply=ask_to_apply,
                    write_to_stdout=write_to_stdout,
                    **kwargs,
                )
            except FileSkipped:
                skipped = True
            return SortAttempt(incorrectly_sorted, skipped)
    except (OSError, ValueError) as error:
        warn(f"Unable to parse file {file_name} due to {error}")
        return None


def iter_source_code(paths: Iterable[str], config: Config, skipped: List[str]) -> Iterator[str]:
    """Iterate over all Python source files defined in paths."""
    visited_dirs: Set[Path] = set()

    for path in paths:
        if os.path.isdir(path):
            for dirpath, dirnames, filenames in os.walk(path, topdown=True, followlinks=True):
                base_path = Path(dirpath)
                for dirname in list(dirnames):
                    full_path = base_path / dirname
                    if config.is_skipped(full_path):
                        skipped.append(dirname)
                        dirnames.remove(dirname)

                    resolved_path = full_path.resolve()
                    if resolved_path in visited_dirs:  # pragma: no cover
                        if not config.quiet:
                            warn(f"Likely recursive symlink detected to {resolved_path}")
                        dirnames.remove(dirname)
                    else:
                        visited_dirs.add(resolved_path)

                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    if config.is_supported_filetype(filepath):
                        if config.is_skipped(Path(filepath)):
                            skipped.append(filename)
                        else:
                            yield filepath
        else:
            yield path


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sort Python import definitions alphabetically "
        "within logical sections. Run with no arguments to see a quick "
        "start guide, otherwise, one or more files/directories/stdin must be provided. "
        "Use `-` as the first argument to represent stdin. Use --interactive to use the pre 5.0.0 "
        "interactive behavior."
        ""
        "If you've used isort 4 but are new to isort 5, see the upgrading guide:"
        "https://timothycrosley.github.io/isort/docs/upgrade_guides/5.0.0/."
    )
    inline_args_group = parser.add_mutually_exclusive_group()
    parser.add_argument(
        "--src",
        "--src-path",
        dest="src_paths",
        action="append",
        help="Add an explicitly defined source path "
        "(modules within src paths have their imports automatically catorgorized as first_party).",
    )
    parser.add_argument(
        "-a",
        "--add-import",
        dest="add_imports",
        action="append",
        help="Adds the specified import line to all files, "
        "automatically determining correct placement.",
    )
    parser.add_argument(
        "--append",
        "--append-only",
        dest="append_only",
        action="store_true",
        help="Only adds the imports specified in --add-imports if the file"
        " contains existing imports.",
    )
    parser.add_argument(
        "--ac",
        "--atomic",
        dest="atomic",
        action="store_true",
        help="Ensures the output doesn't save if the resulting file contains syntax errors.",
    )
    parser.add_argument(
        "--af",
        "--force-adds",
        dest="force_adds",
        action="store_true",
        help="Forces import adds even if the original file is empty.",
    )
    parser.add_argument(
        "-b",
        "--builtin",
        dest="known_standard_library",
        action="append",
        help="Force isort to recognize a module as part of Python's standard library.",
    )
    parser.add_argument(
        "--extra-builtin",
        dest="extra_standard_library",
        action="append",
        help="Extra modules to be included in the list of ones in Python's standard library.",
    )
    parser.add_argument(
        "-c",
        "--check-only",
        "--check",
        action="store_true",
        dest="check",
        help="Checks the file for unsorted / unformatted imports and prints them to the "
        "command line without modifying the file.",
    )
    parser.add_argument(
        "--ca",
        "--combine-as",
        dest="combine_as_imports",
        action="store_true",
        help="Combines as imports on the same line.",
    )
    parser.add_argument(
        "--cs",
        "--combine-star",
        dest="combine_star",
        action="store_true",
        help="Ensures that if a star import is present, "
        "nothing else is imported from that namespace.",
    )
    parser.add_argument(
        "-d",
        "--stdout",
        help="Force resulting output to stdout, instead of in-place.",
        dest="write_to_stdout",
        action="store_true",
    )
    parser.add_argument(
        "--df",
        "--diff",
        dest="show_diff",
        action="store_true",
        help="Prints a diff of all the changes isort would make to a file, instead of "
        "changing it in place",
    )
    parser.add_argument(
        "--ds",
        "--no-sections",
        help="Put all imports into the same section bucket",
        dest="no_sections",
        action="store_true",
    )
    parser.add_argument(
        "-e",
        "--balanced",
        dest="balanced_wrapping",
        action="store_true",
        help="Balances wrapping to produce the most consistent line length possible",
    )
    parser.add_argument(
        "-f",
        "--future",
        dest="known_future_library",
        action="append",
        help="Force isort to recognize a module as part of the future compatibility libraries.",
    )
    parser.add_argument(
        "--fas",
        "--force-alphabetical-sort",
        action="store_true",
        dest="force_alphabetical_sort",
        help="Force all imports to be sorted as a single section",
    )
    parser.add_argument(
        "--fass",
        "--force-alphabetical-sort-within-sections",
        action="store_true",
        dest="force_alphabetical_sort_within_sections",
        help="Force all imports to be sorted alphabetically within a section",
    )
    parser.add_argument(
        "--ff",
        "--from-first",
        dest="from_first",
        help="Switches the typical ordering preference, "
        "showing from imports first then straight ones.",
    )
    parser.add_argument(
        "--fgw",
        "--force-grid-wrap",
        nargs="?",
        const=2,
        type=int,
        dest="force_grid_wrap",
        help="Force number of from imports (defaults to 2) to be grid wrapped regardless of line "
        "length",
    )
    parser.add_argument(
        "--fss",
        "--force-sort-within-sections",
        action="store_true",
        dest="force_sort_within_sections",
        help="Don't sort straight-style imports (like import sys) before from-style imports "
        "(like from itertools import groupby). Instead, sort the imports by module, "
        "independent of import style.",
    )
    parser.add_argument(
        "-i",
        "--indent",
        help='String to place for indents defaults to "    " (4 spaces).',
        dest="indent",
        type=str,
    )
    parser.add_argument(
        "-j", "--jobs", help="Number of files to process in parallel.", dest="jobs", type=int
    )
    parser.add_argument("--lai", "--lines-after-imports", dest="lines_after_imports", type=int)
    parser.add_argument("--lbt", "--lines-between-types", dest="lines_between_types", type=int)
    parser.add_argument(
        "--le",
        "--line-ending",
        dest="line_ending",
        help="Forces line endings to the specified value. "
        "If not set, values will be guessed per-file.",
    )
    parser.add_argument(
        "--ls",
        "--length-sort",
        help="Sort imports by their string length.",
        dest="length_sort",
        action="store_true",
    )
    parser.add_argument(
        "--lss",
        "--length-sort-straight",
        help="Sort straight imports by their string length.",
        dest="length_sort_straight",
        action="store_true",
    )
    parser.add_argument(
        "-m",
        "--multi-line",
        dest="multi_line_output",
        choices=list(WrapModes.__members__.keys())
        + [str(mode.value) for mode in WrapModes.__members__.values()],
        type=str,
        help="Multi line output (0-grid, 1-vertical, 2-hanging, 3-vert-hanging, 4-vert-grid, "
        "5-vert-grid-grouped, 6-vert-grid-grouped-no-comma, 7-noqa, "
        "8-vertical-hanging-indent-bracket, 9-vertical-prefix-from-module-import, "
        "10-hanging-indent-with-parentheses).",
    )
    parser.add_argument(
        "-n",
        "--ensure-newline-before-comments",
        dest="ensure_newline_before_comments",
        action="store_true",
        help="Inserts a blank line before a comment following an import.",
    )
    inline_args_group.add_argument(
        "--nis",
        "--no-inline-sort",
        dest="no_inline_sort",
        action="store_true",
        help="Leaves `from` imports with multiple imports 'as-is' "
        "(e.g. `from foo import a, c ,b`).",
    )
    parser.add_argument(
        "--nlb",
        "--no-lines-before",
        help="Sections which should not be split with previous by empty lines",
        dest="no_lines_before",
        action="append",
    )
    parser.add_argument(
        "-o",
        "--thirdparty",
        dest="known_third_party",
        action="append",
        help="Force isort to recognize a module as being part of a third party library.",
    )
    parser.add_argument(
        "--ot",
        "--order-by-type",
        dest="order_by_type",
        action="store_true",
        help="Order imports by type, which is determined by case, in addition to alphabetically.\n"
        "\n**NOTE**: type here refers to the implied type from the import name capitalization.\n"
        ' isort does not do type introspection for the imports. These "types" are simply: '
        "CONSTANT_VARIABLE, CamelCaseClass, variable_or_function. If your project follows PEP8"
        " or a related coding standard and has many imports this is a good default, otherwise you "
        "likely will want to turn it off. From the CLI the `--dont-order-by-type` option will turn "
        "this off.",
    )
    parser.add_argument(
        "--dt",
        "--dont-order-by-type",
        dest="dont_order_by_type",
        action="store_true",
        help="Don't order imports by type, which is determined by case, in addition to "
        "alphabetically.\n\n"
        "**NOTE**: type here refers to the implied type from the import name capitalization.\n"
        ' isort does not do type introspection for the imports. These "types" are simply: '
        "CONSTANT_VARIABLE, CamelCaseClass, variable_or_function. If your project follows PEP8"
        " or a related coding standard and has many imports this is a good default. You can turn "
        "this on from the CLI using `--order-by-type`.",
    )
    parser.add_argument(
        "-p",
        "--project",
        dest="known_first_party",
        action="append",
        help="Force isort to recognize a module as being part of the current python project.",
    )
    parser.add_argument(
        "--known-local-folder",
        dest="known_local_folder",
        action="append",
        help="Force isort to recognize a module as being a local folder. "
        "Generally, this is reserved for relative imports (from . import module).",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        dest="quiet",
        help="Shows extra quiet output, only errors are outputted.",
    )
    parser.add_argument(
        "--rm",
        "--remove-import",
        dest="remove_imports",
        action="append",
        help="Removes the specified import from all files.",
    )
    parser.add_argument(
        "--rr",
        "--reverse-relative",
        dest="reverse_relative",
        action="store_true",
        help="Reverse order of relative imports.",
    )
    parser.add_argument(
        "-s",
        "--skip",
        help="Files that sort imports should skip over. If you want to skip multiple "
        "files you should specify twice: --skip file1 --skip file2.",
        dest="skip",
        action="append",
    )
    parser.add_argument(
        "--sd",
        "--section-default",
        dest="default_section",
        help="Sets the default section for import options: " + str(sections.DEFAULT),
    )
    parser.add_argument(
        "--sg",
        "--skip-glob",
        help="Files that sort imports should skip over.",
        dest="skip_glob",
        action="append",
    )
    parser.add_argument(
        "--gitignore",
        "--skip-gitignore",
        action="store_true",
        dest="skip_gitignore",
        help="Treat project as a git repository and ignore files listed in .gitignore",
    )
    inline_args_group.add_argument(
        "--sl",
        "--force-single-line-imports",
        dest="force_single_line",
        action="store_true",
        help="Forces all from imports to appear on their own line",
    )
    parser.add_argument(
        "--nsl",
        "--single-line-exclusions",
        help="One or more modules to exclude from the single line rule.",
        dest="single_line_exclusions",
        action="append",
    )
    parser.add_argument(
        "--sp",
        "--settings-path",
        "--settings-file",
        "--settings",
        dest="settings_path",
        help="Explicitly set the settings path or file instead of auto determining "
        "based on file location.",
    )
    parser.add_argument(
        "-t",
        "--top",
        help="Force specific imports to the top of their appropriate section.",
        dest="force_to_top",
        action="append",
    )
    parser.add_argument(
        "--tc",
        "--trailing-comma",
        dest="include_trailing_comma",
        action="store_true",
        help="Includes a trailing comma on multi line imports that include parentheses.",
    )
    parser.add_argument(
        "--up",
        "--use-parentheses",
        dest="use_parentheses",
        action="store_true",
        help="Use parentheses for line continuation on length limit instead of slashes."
        " **NOTE**: This is separate from wrap modes, and only affects how individual lines that "
        " are too long get continued, not sections of multiple imports.",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="store_true",
        dest="show_version",
        help="Displays the currently installed version of isort.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        dest="verbose",
        help="Shows verbose output, such as when files are skipped or when a check is successful.",
    )
    parser.add_argument(
        "--virtual-env",
        dest="virtual_env",
        help="Virtual environment to use for determining whether a package is third-party",
    )
    parser.add_argument(
        "--conda-env",
        dest="conda_env",
        help="Conda environment to use for determining whether a package is third-party",
    )
    parser.add_argument(
        "--vn",
        "--version-number",
        action="version",
        version=__version__,
        help="Returns just the current version number without the logo",
    )
    parser.add_argument(
        "-l",
        "-w",
        "--line-length",
        "--line-width",
        help="The max length of an import line (used for wrapping long imports).",
        dest="line_length",
        type=int,
    )
    parser.add_argument(
        "--wl",
        "--wrap-length",
        dest="wrap_length",
        type=int,
        help="Specifies how long lines that are wrapped should be, if not set line_length is used."
        "\nNOTE: wrap_length must be LOWER than or equal to line_length.",
    )
    parser.add_argument(
        "--ws",
        "--ignore-whitespace",
        action="store_true",
        dest="ignore_whitespace",
        help="Tells isort to ignore whitespace differences when --check-only is being used.",
    )
    parser.add_argument(
        "--case-sensitive",
        dest="case_sensitive",
        action="store_true",
        help="Tells isort to include casing when sorting module names",
    )
    parser.add_argument(
        "--filter-files",
        dest="filter_files",
        action="store_true",
        help="Tells isort to filter files even when they are explicitly passed in as "
        "part of the CLI command.",
    )
    parser.add_argument(
        "files", nargs="*", help="One or more Python source files that need their imports sorted."
    )
    parser.add_argument(
        "--py",
        "--python-version",
        action="store",
        dest="py_version",
        choices=tuple(VALID_PY_TARGETS) + ("auto",),
        help="Tells isort to set the known standard library based on the the specified Python "
        "version. Default is to assume any Python 3 version could be the target, and use a union "
        "off all stdlib modules across versions. If auto is specified, the version of the "
        "interpreter used to run isort "
        f"(currently: {sys.version_info.major}{sys.version_info.minor}) will be used.",
    )
    parser.add_argument(
        "--profile",
        dest="profile",
        type=str,
        help="Base profile type to use for configuration. "
        f"Profiles include: {', '.join(profiles.keys())}. As well as any shared profiles.",
    )
    parser.add_argument(
        "--interactive",
        dest="ask_to_apply",
        action="store_true",
        help="Tells isort to apply changes interactively.",
    )
    parser.add_argument(
        "--old-finders",
        "--magic-placement",
        dest="old_finders",
        action="store_true",
        help="Use the old deprecated finder logic that relies on environment introspection magic.",
    )
    parser.add_argument(
        "--show-config",
        dest="show_config",
        action="store_true",
        help="See isort's determined config, as well as sources of config options.",
    )
    parser.add_argument(
        "--honor-noqa",
        dest="honor_noqa",
        action="store_true",
        help="Tells isort to honor noqa comments to enforce skipping those comments.",
    )
    parser.add_argument(
        "--remove-redundant-aliases",
        dest="remove_redundant_aliases",
        action="store_true",
        help=(
            "Tells isort to remove redundant aliases from imports, such as `import os as os`."
            " This defaults to `False` simply because some projects use these seemingly useless "
            " aliases to signify intent and change behaviour."
        ),
    )
    parser.add_argument(
        "--color",
        dest="color_output",
        action="store_true",
        help="Tells isort to use color in terminal output.",
    )
    parser.add_argument(
        "--float-to-top",
        dest="float_to_top",
        action="store_true",
        help="Causes all non-indented imports to float to the top of the file having its imports "
        "sorted.  It can be an excellent shortcut for collecting imports every once in a while "
        "when you place them in the middle of a file to avoid context switching.\n\n"
        "*NOTE*: It currently doesn't work with cimports and introduces some extra over-head "
        "and a performance penalty.",
    )
    parser.add_argument(
        "--treat-comment-as-code",
        dest="treat_comments_as_code",
        action="append",
        help="Tells isort to treat the specified single line comment(s) as if they are code.",
    )
    parser.add_argument(
        "--treat-all-comment-as-code",
        dest="treat_all_comments_as_code",
        action="store_true",
        help="Tells isort to treat all single line comments as if they are code.",
    )
    parser.add_argument(
        "--formatter",
        dest="formatter",
        type=str,
        help="Specifies the name of a formatting plugin to use when producing output.",
    )
    parser.add_argument(
        "--ext",
        "--extension",
        "--supported-extension",
        dest="supported_extensions",
        action="append",
        help="Specifies what extensions isort can be ran against.",
    )
    parser.add_argument(
        "--blocked-extension",
        dest="blocked_extensions",
        action="append",
        help="Specifies what extensions isort can never be ran against.",
    )
    parser.add_argument(
        "--dedup-headings",
        dest="dedup_headings",
        action="store_true",
        help="Tells isort to only show an identical custom import heading comment once, even if"
        " there are multiple sections with the comment set.",
    )

    # deprecated options
    parser.add_argument(
        "--recursive",
        dest="deprecated_flags",
        action="append_const",
        const="--recursive",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-rc", dest="deprecated_flags", action="append_const", const="-rc", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--dont-skip",
        dest="deprecated_flags",
        action="append_const",
        const="--dont-skip",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-ns", dest="deprecated_flags", action="append_const", const="-ns", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--apply",
        dest="deprecated_flags",
        action="append_const",
        const="--apply",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-k",
        "--keep-direct-and-as",
        dest="deprecated_flags",
        action="append_const",
        const="--keep-direct-and-as",
        help=argparse.SUPPRESS,
    )

    return parser


def parse_args(argv: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    argv = sys.argv[1:] if argv is None else list(argv)
    remapped_deprecated_args = []
    for index, arg in enumerate(argv):
        if arg in DEPRECATED_SINGLE_DASH_ARGS:
            remapped_deprecated_args.append(arg)
            argv[index] = f"-{arg}"

    parser = _build_arg_parser()
    arguments = {key: value for key, value in vars(parser.parse_args(argv)).items() if value}
    if remapped_deprecated_args:
        arguments["remapped_deprecated_args"] = remapped_deprecated_args
    if "dont_order_by_type" in arguments:
        arguments["order_by_type"] = False
        del arguments["dont_order_by_type"]
    multi_line_output = arguments.get("multi_line_output", None)
    if multi_line_output:
        if multi_line_output.isdigit():
            arguments["multi_line_output"] = WrapModes(int(multi_line_output))
        else:
            arguments["multi_line_output"] = WrapModes[multi_line_output]
    return arguments


def _preconvert(item):
    """Preconverts objects from native types into JSONifyiable types"""
    if isinstance(item, (set, frozenset)):
        return list(item)
    elif isinstance(item, WrapModes):
        return item.name
    elif isinstance(item, Path):
        return str(item)
    elif callable(item) and hasattr(item, "__name__"):
        return item.__name__
    else:
        raise TypeError("Unserializable object {} of type {}".format(item, type(item)))


def main(argv: Optional[Sequence[str]] = None, stdin: Optional[TextIOWrapper] = None) -> None:
    arguments = parse_args(argv)
    if arguments.get("show_version"):
        print(ASCII_ART)
        return

    show_config: bool = arguments.pop("show_config", False)

    if "settings_path" in arguments:
        if os.path.isfile(arguments["settings_path"]):
            arguments["settings_file"] = os.path.abspath(arguments["settings_path"])
            arguments["settings_path"] = os.path.dirname(arguments["settings_file"])
        else:
            arguments["settings_path"] = os.path.abspath(arguments["settings_path"])

    if "virtual_env" in arguments:
        venv = arguments["virtual_env"]
        arguments["virtual_env"] = os.path.abspath(venv)
        if not os.path.isdir(arguments["virtual_env"]):
            warn(f"virtual_env dir does not exist: {arguments['virtual_env']}")

    file_names = arguments.pop("files", [])
    if not file_names and not show_config:
        print(QUICK_GUIDE)
        if arguments:
            sys.exit("Error: arguments passed in without any paths or content.")
        else:
            return
    if "settings_path" not in arguments:
        arguments["settings_path"] = (
            os.path.abspath(file_names[0] if file_names else ".") or os.getcwd()
        )
        if not os.path.isdir(arguments["settings_path"]):
            arguments["settings_path"] = os.path.dirname(arguments["settings_path"])

    config_dict = arguments.copy()
    ask_to_apply = config_dict.pop("ask_to_apply", False)
    jobs = config_dict.pop("jobs", ())
    check = config_dict.pop("check", False)
    show_diff = config_dict.pop("show_diff", False)
    write_to_stdout = config_dict.pop("write_to_stdout", False)
    deprecated_flags = config_dict.pop("deprecated_flags", False)
    remapped_deprecated_args = config_dict.pop("remapped_deprecated_args", False)
    wrong_sorted_files = False

    if "src_paths" in config_dict:
        config_dict["src_paths"] = {
            Path(src_path).resolve() for src_path in config_dict.get("src_paths", ())
        }

    config = Config(**config_dict)
    if show_config:
        print(json.dumps(config.__dict__, indent=4, separators=(",", ": "), default=_preconvert))
        return
    elif file_names == ["-"]:
        arguments.setdefault("settings_path", os.getcwd())
        api.sort_stream(
            input_stream=sys.stdin if stdin is None else stdin,
            output_stream=sys.stdout,
            **arguments,
        )
    else:
        skipped: List[str] = []

        if config.filter_files:
            filtered_files = []
            for file_name in file_names:
                if config.is_skipped(Path(file_name)):
                    skipped.append(file_name)
                else:
                    filtered_files.append(file_name)
            file_names = filtered_files

        file_names = iter_source_code(file_names, config, skipped)
        num_skipped = 0
        if config.verbose:
            print(ASCII_ART)

        if jobs:
            import multiprocessing

            executor = multiprocessing.Pool(jobs)
            attempt_iterator = executor.imap(
                functools.partial(
                    sort_imports,
                    config=config,
                    check=check,
                    ask_to_apply=ask_to_apply,
                    write_to_stdout=write_to_stdout,
                ),
                file_names,
            )
        else:
            # https://github.com/python/typeshed/pull/2814
            attempt_iterator = (
                sort_imports(  # type: ignore
                    file_name,
                    config=config,
                    check=check,
                    ask_to_apply=ask_to_apply,
                    show_diff=show_diff,
                    write_to_stdout=write_to_stdout,
                )
                for file_name in file_names
            )

        for sort_attempt in attempt_iterator:
            if not sort_attempt:
                continue  # pragma: no cover - shouldn't happen, satisfies type constraint
            incorrectly_sorted = sort_attempt.incorrectly_sorted
            if arguments.get("check", False) and incorrectly_sorted:
                wrong_sorted_files = True
            if sort_attempt.skipped:
                num_skipped += (
                    1  # pragma: no cover - shouldn't happen, due to skip in iter_source_code
                )

        num_skipped += len(skipped)
        if num_skipped and not arguments.get("quiet", False):
            if config.verbose:
                for was_skipped in skipped:
                    warn(
                        f"{was_skipped} was skipped as it's listed in 'skip' setting"
                        " or matches a glob in 'skip_glob' setting"
                    )
            print(f"Skipped {num_skipped} files")

    if not config.quiet and (remapped_deprecated_args or deprecated_flags):
        if remapped_deprecated_args:
            warn(
                "W0502: The following deprecated single dash CLI flags were used and translated: "
                f"{', '.join(remapped_deprecated_args)}!"
            )
        if deprecated_flags:
            warn(
                "W0501: The following deprecated CLI flags were used and ignored: "
                f"{', '.join(deprecated_flags)}!"
            )
        warn(
            "W0500: Please see the 5.0.0 Upgrade guide: "
            "https://timothycrosley.github.io/isort/docs/upgrade_guides/5.0.0/"
        )

    if wrong_sorted_files:
        sys.exit(1)


if __name__ == "__main__":
    main()
