# Licensed under the GPL: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
# For details: https://github.com/PyCQA/pylint/blob/master/COPYING

import collections
import functools

from pylint import reporters
from pylint.lint.utils import _patch_sys_path
from pylint.message import Message

try:
    import multiprocessing
except ImportError:
    multiprocessing = None  # type: ignore

# PyLinter object used by worker processes when checking files using multiprocessing
# should only be used by the worker processes
_worker_linter = None


def _get_new_args(message):
    location = (
        message.abspath,
        message.path,
        message.module,
        message.obj,
        message.line,
        message.column,
    )
    return (message.msg_id, message.symbol, location, message.msg, message.confidence)


def _merge_stats(stats):
    merged = {}
    by_msg = collections.Counter()
    for stat in stats:
        message_stats = stat.pop("by_msg", {})
        by_msg.update(message_stats)

        for key, item in stat.items():
            if key not in merged:
                merged[key] = item
            elif isinstance(item, dict):
                merged[key].update(item)
            else:
                merged[key] = merged[key] + item

    merged["by_msg"] = by_msg
    return merged


def _worker_initialize(linter, arguments=None):
    global _worker_linter  # pylint: disable=global-statement
    _worker_linter = linter

    # On the worker process side the messages are just collected and passed back to
    # parent process as _worker_check_file function's return value
    _worker_linter.set_reporter(reporters.CollectingReporter())
    _worker_linter.open()

    # Patch sys.path so that each argument is importable just like in single job mode
    _patch_sys_path(arguments or ())


def _worker_check_single_file(file_item):
    name, filepath, modname = file_item

    _worker_linter.open()
    _worker_linter.check_single_file(name, filepath, modname)

    msgs = [_get_new_args(m) for m in _worker_linter.reporter.messages]
    return (
        _worker_linter.current_name,
        filepath,
        _worker_linter.file_state.base_name,
        msgs,
        _worker_linter.stats,
        _worker_linter.msg_status,
    )


def check_parallel(linter, jobs, files, arguments=None):
    """Use the given linter to lint the files with given amount of workers (jobs)"""
    # The reporter does not need to be passed to worker processess, i.e. the reporter does
    # not need to be pickleable
    original_reporter = linter.reporter
    linter.reporter = None

    # The linter is inherited by all the pool's workers, i.e. the linter
    # is identical to the linter object here. This is requred so that
    # a custom PyLinter object can be used.
    initializer = functools.partial(_worker_initialize, arguments=arguments)
    with multiprocessing.Pool(jobs, initializer=initializer, initargs=[linter]) as pool:
        # ..and now when the workers have inherited the linter, the actual reporter
        # can be set back here on the parent process so that results get stored into
        # correct reporter
        linter.set_reporter(original_reporter)
        linter.open()

        all_stats = []

        for (
            module,
            file_path,
            base_name,
            messages,
            stats,
            msg_status,
        ) in pool.imap_unordered(_worker_check_single_file, files):
            linter.file_state.base_name = base_name
            linter.set_current_module(module, file_path)
            for msg in messages:
                msg = Message(*msg)
                linter.reporter.handle_message(msg)

            all_stats.append(stats)
            linter.msg_status |= msg_status

    linter.stats = _merge_stats(all_stats)

    # Insert stats data to local checkers.
    for checker in linter.get_checkers():
        if checker is not linter:
            checker.stats = linter.stats
