import shutil
import sys
from io import StringIO
from pathlib import Path
from typing import Optional, TextIO, Union, cast
from warnings import warn

from isort import core

from . import io
from .exceptions import (
    ExistingSyntaxErrors,
    FileSkipComment,
    FileSkipSetting,
    IntroducedSyntaxErrors,
)
from .format import ask_whether_to_apply_changes_to_file, create_terminal_printer, show_unified_diff
from .io import Empty
from .place import module as place_module  # noqa: F401
from .place import module_with_reason as place_module_with_reason  # noqa: F401
from .settings import DEFAULT_CONFIG, Config


def sort_code_string(
    code: str,
    extension: Optional[str] = None,
    config: Config = DEFAULT_CONFIG,
    file_path: Optional[Path] = None,
    disregard_skip: bool = False,
    show_diff: Union[bool, TextIO] = False,
    **config_kwargs,
):
    """Sorts any imports within the provided code string, returning a new string with them sorted.

    - **code**: The string of code with imports that need to be sorted.
    - **extension**: The file extension that contains imports. Defaults to filename extension or py.
    - **config**: The config object to use when sorting imports.
    - **file_path**: The disk location where the code string was pulled from.
    - **disregard_skip**: set to `True` if you want to ignore a skip set in config for this file.
    - **show_diff**: If `True` the changes that need to be done will be printed to stdout, if a
    TextIO stream is provided results will be written to it, otherwise no diff will be computed.
    - ****config_kwargs**: Any config modifications.
    """
    input_stream = StringIO(code)
    output_stream = StringIO()
    config = _config(path=file_path, config=config, **config_kwargs)
    sort_stream(
        input_stream,
        output_stream,
        extension=extension,
        config=config,
        file_path=file_path,
        disregard_skip=disregard_skip,
        show_diff=show_diff,
    )
    output_stream.seek(0)
    return output_stream.read()


def check_code_string(
    code: str,
    show_diff: Union[bool, TextIO] = False,
    extension: Optional[str] = None,
    config: Config = DEFAULT_CONFIG,
    file_path: Optional[Path] = None,
    disregard_skip: bool = False,
    **config_kwargs,
) -> bool:
    """Checks the order, format, and categorization of imports within the provided code string.
    Returns `True` if everything is correct, otherwise `False`.

    - **code**: The string of code with imports that need to be sorted.
    - **show_diff**: If `True` the changes that need to be done will be printed to stdout, if a
    TextIO stream is provided results will be written to it, otherwise no diff will be computed.
    - **extension**: The file extension that contains imports. Defaults to filename extension or py.
    - **config**: The config object to use when sorting imports.
    - **file_path**: The disk location where the code string was pulled from.
    - **disregard_skip**: set to `True` if you want to ignore a skip set in config for this file.
    - ****config_kwargs**: Any config modifications.
    """
    config = _config(path=file_path, config=config, **config_kwargs)
    return check_stream(
        StringIO(code),
        show_diff=show_diff,
        extension=extension,
        config=config,
        file_path=file_path,
        disregard_skip=disregard_skip,
    )


def sort_stream(
    input_stream: TextIO,
    output_stream: TextIO,
    extension: Optional[str] = None,
    config: Config = DEFAULT_CONFIG,
    file_path: Optional[Path] = None,
    disregard_skip: bool = False,
    show_diff: Union[bool, TextIO] = False,
    **config_kwargs,
) -> bool:
    """Sorts any imports within the provided code stream, outputs to the provided output stream.
     Returns `True` if anything is modified from the original input stream, otherwise `False`.

    - **input_stream**: The stream of code with imports that need to be sorted.
    - **output_stream**: The stream where sorted imports should be written to.
    - **extension**: The file extension that contains imports. Defaults to filename extension or py.
    - **config**: The config object to use when sorting imports.
    - **file_path**: The disk location where the code string was pulled from.
    - **disregard_skip**: set to `True` if you want to ignore a skip set in config for this file.
    - **show_diff**: If `True` the changes that need to be done will be printed to stdout, if a
    TextIO stream is provided results will be written to it, otherwise no diff will be computed.
    - ****config_kwargs**: Any config modifications.
    """
    if show_diff:
        _output_stream = StringIO()
        _input_stream = StringIO(input_stream.read())
        changed = sort_stream(
            input_stream=_input_stream,
            output_stream=_output_stream,
            extension=extension,
            config=config,
            file_path=file_path,
            disregard_skip=disregard_skip,
            **config_kwargs,
        )
        _output_stream.seek(0)
        _input_stream.seek(0)
        show_unified_diff(
            file_input=_input_stream.read(),
            file_output=_output_stream.read(),
            file_path=file_path,
            output=output_stream if show_diff is True else cast(TextIO, show_diff),
        )
        return changed

    config = _config(path=file_path, config=config, **config_kwargs)
    content_source = str(file_path or "Passed in content")
    if not disregard_skip:
        if file_path and config.is_skipped(file_path):
            raise FileSkipSetting(content_source)

    _internal_output = output_stream

    if config.atomic:
        try:
            file_content = input_stream.read()
            compile(file_content, content_source, "exec", 0, 1)
            input_stream = StringIO(file_content)
        except SyntaxError:
            raise ExistingSyntaxErrors(content_source)

        if not output_stream.readable():
            _internal_output = StringIO()

    try:
        changed = core.process(
            input_stream,
            _internal_output,
            extension=extension or (file_path and file_path.suffix.lstrip(".")) or "py",
            config=config,
        )
    except FileSkipComment:
        raise FileSkipComment(content_source)

    if config.atomic:
        _internal_output.seek(0)
        try:
            compile(_internal_output.read(), content_source, "exec", 0, 1)
            _internal_output.seek(0)
            if _internal_output != output_stream:
                output_stream.write(_internal_output.read())
        except SyntaxError:  # pragma: no cover
            raise IntroducedSyntaxErrors(content_source)

    return changed


def check_stream(
    input_stream: TextIO,
    show_diff: Union[bool, TextIO] = False,
    extension: Optional[str] = None,
    config: Config = DEFAULT_CONFIG,
    file_path: Optional[Path] = None,
    disregard_skip: bool = False,
    **config_kwargs,
) -> bool:
    """Checks any imports within the provided code stream, returning `False` if any unsorted or
    incorrectly imports are found or `True` if no problems are identified.

    - **input_stream**: The stream of code with imports that need to be sorted.
    - **show_diff**: If `True` the changes that need to be done will be printed to stdout, if a
    TextIO stream is provided results will be written to it, otherwise no diff will be computed.
    - **extension**: The file extension that contains imports. Defaults to filename extension or py.
    - **config**: The config object to use when sorting imports.
    - **file_path**: The disk location where the code string was pulled from.
    - **disregard_skip**: set to `True` if you want to ignore a skip set in config for this file.
    - ****config_kwargs**: Any config modifications.
    """
    config = _config(path=file_path, config=config, **config_kwargs)

    changed: bool = sort_stream(
        input_stream=input_stream,
        output_stream=Empty,
        extension=extension,
        config=config,
        file_path=file_path,
        disregard_skip=disregard_skip,
    )
    printer = create_terminal_printer(color=config.color_output)
    if not changed:
        if config.verbose:
            printer.success(f"{file_path or ''} Everything Looks Good!")
        return True
    else:
        printer.error(f"{file_path or ''} Imports are incorrectly sorted and/or formatted.")
        if show_diff:
            output_stream = StringIO()
            input_stream.seek(0)
            file_contents = input_stream.read()
            sort_stream(
                input_stream=StringIO(file_contents),
                output_stream=output_stream,
                extension=extension,
                config=config,
                file_path=file_path,
                disregard_skip=disregard_skip,
            )
            output_stream.seek(0)

            show_unified_diff(
                file_input=file_contents,
                file_output=output_stream.read(),
                file_path=file_path,
                output=None if show_diff is True else cast(TextIO, show_diff),
            )
        return False


def check_file(
    filename: Union[str, Path],
    show_diff: Union[bool, TextIO] = False,
    config: Config = DEFAULT_CONFIG,
    file_path: Optional[Path] = None,
    disregard_skip: bool = True,
    extension: Optional[str] = None,
    **config_kwargs,
) -> bool:
    """Checks any imports within the provided file, returning `False` if any unsorted or
    incorrectly imports are found or `True` if no problems are identified.

    - **filename**: The name or Path of the file to check.
    - **show_diff**: If `True` the changes that need to be done will be printed to stdout, if a
    TextIO stream is provided results will be written to it, otherwise no diff will be computed.
    - **config**: The config object to use when sorting imports.
    - **file_path**: The disk location where the code string was pulled from.
    - **disregard_skip**: set to `True` if you want to ignore a skip set in config for this file.
    - **extension**: The file extension that contains imports. Defaults to filename extension or py.
    - ****config_kwargs**: Any config modifications.
    """
    with io.File.read(filename) as source_file:
        return check_stream(
            source_file.stream,
            show_diff=show_diff,
            extension=extension,
            config=config,
            file_path=file_path or source_file.path,
            disregard_skip=disregard_skip,
            **config_kwargs,
        )


def sort_file(
    filename: Union[str, Path],
    extension: Optional[str] = None,
    config: Config = DEFAULT_CONFIG,
    file_path: Optional[Path] = None,
    disregard_skip: bool = True,
    ask_to_apply: bool = False,
    show_diff: Union[bool, TextIO] = False,
    write_to_stdout: bool = False,
    **config_kwargs,
) -> bool:
    """Sorts and formats any groups of imports imports within the provided file or Path.
     Returns `True` if the file has been changed, otherwise `False`.

    - **filename**: The name or Path of the file to format.
    - **extension**: The file extension that contains imports. Defaults to filename extension or py.
    - **config**: The config object to use when sorting imports.
    - **file_path**: The disk location where the code string was pulled from.
    - **disregard_skip**: set to `True` if you want to ignore a skip set in config for this file.
    - **ask_to_apply**: If `True`, prompt before applying any changes.
    - **show_diff**: If `True` the changes that need to be done will be printed to stdout, if a
    TextIO stream is provided results will be written to it, otherwise no diff will be computed.
    - **write_to_stdout**: If `True`, write to stdout instead of the input file.
    - ****config_kwargs**: Any config modifications.
    """
    with io.File.read(filename) as source_file:
        changed: bool = False
        try:
            if write_to_stdout:
                changed = sort_stream(
                    input_stream=source_file.stream,
                    output_stream=sys.stdout,
                    config=config,
                    file_path=file_path or source_file.path,
                    disregard_skip=disregard_skip,
                    extension=extension,
                    **config_kwargs,
                )
            else:
                tmp_file = source_file.path.with_suffix(source_file.path.suffix + ".isorted")
                try:
                    with tmp_file.open(
                        "w", encoding=source_file.encoding, newline=""
                    ) as output_stream:
                        shutil.copymode(filename, tmp_file)
                        changed = sort_stream(
                            input_stream=source_file.stream,
                            output_stream=output_stream,
                            config=config,
                            file_path=file_path or source_file.path,
                            disregard_skip=disregard_skip,
                            extension=extension,
                            **config_kwargs,
                        )
                    if changed:
                        if show_diff or ask_to_apply:
                            source_file.stream.seek(0)
                            with tmp_file.open(
                                encoding=source_file.encoding, newline=""
                            ) as tmp_out:
                                show_unified_diff(
                                    file_input=source_file.stream.read(),
                                    file_output=tmp_out.read(),
                                    file_path=file_path or source_file.path,
                                    output=None if show_diff is True else cast(TextIO, show_diff),
                                )
                                if show_diff or (
                                    ask_to_apply
                                    and not ask_whether_to_apply_changes_to_file(
                                        str(source_file.path)
                                    )
                                ):
                                    return False
                        source_file.stream.close()
                        tmp_file.replace(source_file.path)
                        if not config.quiet:
                            print(f"Fixing {source_file.path}")
                finally:
                    try:  # Python 3.8+: use `missing_ok=True` instead of try except.
                        tmp_file.unlink()
                    except FileNotFoundError:
                        pass
        except ExistingSyntaxErrors:
            warn(f"{file_path} unable to sort due to existing syntax errors")
        except IntroducedSyntaxErrors:  # pragma: no cover
            warn(f"{file_path} unable to sort as isort introduces new syntax errors")

        return changed


def _config(
    path: Optional[Path] = None, config: Config = DEFAULT_CONFIG, **config_kwargs
) -> Config:
    if path:
        if (
            config is DEFAULT_CONFIG
            and "settings_path" not in config_kwargs
            and "settings_file" not in config_kwargs
        ):
            config_kwargs["settings_path"] = path

    if config_kwargs:
        if config is not DEFAULT_CONFIG:
            raise ValueError(
                "You can either specify custom configuration options using kwargs or "
                "passing in a Config object. Not Both!"
            )

        config = Config(**config_kwargs)

    return config
