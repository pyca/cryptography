# -*- coding: utf-8 -*-
# Copyright (c) 2012-2014 LOGILAB S.A. (Paris, FRANCE) <contact@logilab.fr>
# Copyright (c) 2012 FELD Boris <lothiraldan@gmail.com>
# Copyright (c) 2013-2018, 2020 Claudiu Popa <pcmanticore@gmail.com>
# Copyright (c) 2013-2014 Google, Inc.
# Copyright (c) 2013 buck@yelp.com <buck@yelp.com>
# Copyright (c) 2014 LCD 47 <lcd047@gmail.com>
# Copyright (c) 2014 Brett Cannon <brett@python.org>
# Copyright (c) 2014 Ricardo Gemignani <ricardo.gemignani@gmail.com>
# Copyright (c) 2014 Arun Persaud <arun@nubati.net>
# Copyright (c) 2015 Pavel Roskin <proski@gnu.org>
# Copyright (c) 2015 Ionel Cristian Maries <contact@ionelmc.ro>
# Copyright (c) 2016 Derek Gustafson <degustaf@gmail.com>
# Copyright (c) 2016 Roy Williams <roy.williams.iii@gmail.com>
# Copyright (c) 2016 xmo-odoo <xmo-odoo@users.noreply.github.com>
# Copyright (c) 2017 Bryce Guinta <bryce.paul.guinta@gmail.com>
# Copyright (c) 2018 ssolanki <sushobhitsolanki@gmail.com>
# Copyright (c) 2018 Sushobhit <31987769+sushobhit27@users.noreply.github.com>
# Copyright (c) 2019 Mr. Senko <atodorov@mrsenko.com>
# Copyright (c) 2019 Hugo van Kemenade <hugovk@users.noreply.github.com>
# Copyright (c) 2019 Pierre Sassoulas <pierre.sassoulas@gmail.com>
# Copyright (c) 2020 谭九鼎 <109224573@qq.com>
# Copyright (c) 2020 Anthony Sottile <asottile@umich.edu>

# Licensed under the GPL: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
# For details: https://github.com/PyCQA/pylint/blob/master/COPYING

"""functional/non regression tests for pylint"""
import collections
import configparser
import contextlib
import csv
import functools
import operator
import platform
import re
import sys
import tempfile
import tokenize
from glob import glob
from io import StringIO
from os import close, getcwd, linesep, remove, sep, write
from os.path import abspath, basename, dirname, exists, join, splitext

import astroid
import pytest

from pylint import checkers, interfaces
from pylint.lint import PyLinter
from pylint.reporters import BaseReporter
from pylint.utils import ASTWalker

# Utils

SYS_VERS_STR = "%d%d%d" % sys.version_info[:3]
TITLE_UNDERLINES = ["", "=", "-", "."]
PREFIX = abspath(dirname(__file__))


def _get_tests_info(input_dir, msg_dir, prefix, suffix):
    """get python input examples and output messages

    We use following conventions for input files and messages:
    for different inputs:
        test for python  >= x.y    ->  input   =  <name>_pyxy.py
        test for python  <  x.y    ->  input   =  <name>_py_xy.py
    for one input and different messages:
        message for python >=  x.y ->  message =  <name>_pyxy.txt
        lower versions             ->  message with highest num
    """
    result = []
    for fname in glob(join(input_dir, prefix + "*" + suffix)):
        infile = basename(fname)
        fbase = splitext(infile)[0]
        # filter input files :
        pyrestr = fbase.rsplit("_py", 1)[-1]  # like _26 or 26
        if pyrestr.isdigit():  # '24', '25'...
            if SYS_VERS_STR < pyrestr:
                continue
        if pyrestr.startswith("_") and pyrestr[1:].isdigit():
            # skip test for higher python versions
            if SYS_VERS_STR >= pyrestr[1:]:
                continue
        messages = glob(join(msg_dir, fbase + "*.txt"))
        # the last one will be without ext, i.e. for all or upper versions:
        if messages:
            for outfile in sorted(messages, reverse=True):
                py_rest = outfile.rsplit("_py", 1)[-1][:-4]
                if py_rest.isdigit() and SYS_VERS_STR >= py_rest:
                    break
        else:
            # This will provide an error message indicating the missing filename.
            outfile = join(msg_dir, fbase + ".txt")
        result.append((infile, outfile))
    return result


class TestReporter(BaseReporter):
    """reporter storing plain text messages"""

    __implements__ = interfaces.IReporter

    def __init__(self):  # pylint: disable=super-init-not-called

        self.message_ids = {}
        self.reset()
        self.path_strip_prefix = getcwd() + sep

    def reset(self):
        self.out = StringIO()
        self.messages = []

    def handle_message(self, msg):
        """manage message of different type and in the context of path """
        obj = msg.obj
        line = msg.line
        msg_id = msg.msg_id
        msg = msg.msg
        self.message_ids[msg_id] = 1
        if obj:
            obj = ":%s" % obj
        sigle = msg_id[0]
        if linesep != "\n":
            # 2to3 writes os.linesep instead of using
            # the previosly used line separators
            msg = msg.replace("\r\n", "\n")
        self.messages.append("%s:%3s%s: %s" % (sigle, line, obj, msg))

    def finalize(self):
        self.messages.sort()
        for msg in self.messages:
            print(msg, file=self.out)
        result = self.out.getvalue()
        self.reset()
        return result

    # pylint: disable=unused-argument
    def on_set_current_module(self, module, filepath):
        pass

    # pylint: enable=unused-argument

    def display_reports(self, layout):
        """ignore layouts"""

    _display = None


class MinimalTestReporter(BaseReporter):
    def handle_message(self, msg):
        self.messages.append(msg)

    def on_set_current_module(self, module, filepath):
        self.messages = []

    _display = None


class Message(
    collections.namedtuple("Message", ["msg_id", "line", "node", "args", "confidence"])
):
    def __new__(cls, msg_id, line=None, node=None, args=None, confidence=None):
        return tuple.__new__(cls, (msg_id, line, node, args, confidence))

    def __eq__(self, other):
        if isinstance(other, Message):
            if self.confidence and other.confidence:
                return super().__eq__(other)
            return self[:-1] == other[:-1]
        return NotImplemented  # pragma: no cover

    __hash__ = None


class UnittestLinter:
    """A fake linter class to capture checker messages."""

    # pylint: disable=unused-argument, no-self-use

    def __init__(self):
        self._messages = []
        self.stats = {}

    def release_messages(self):
        try:
            return self._messages
        finally:
            self._messages = []

    def add_message(
        self, msg_id, line=None, node=None, args=None, confidence=None, col_offset=None
    ):
        # Do not test col_offset for now since changing Message breaks everything
        self._messages.append(Message(msg_id, line, node, args, confidence))

    def is_message_enabled(self, *unused_args, **unused_kwargs):
        return True

    def add_stats(self, **kwargs):
        for name, value in kwargs.items():
            self.stats[name] = value
        return self.stats

    @property
    def options_providers(self):
        return linter.options_providers


def set_config(**kwargs):
    """Decorator for setting config values on a checker."""

    def _wrapper(fun):
        @functools.wraps(fun)
        def _forward(self):
            for key, value in kwargs.items():
                setattr(self.checker.config, key, value)
            if isinstance(self, CheckerTestCase):
                # reopen checker in case, it may be interested in configuration change
                self.checker.open()
            fun(self)

        return _forward

    return _wrapper


class CheckerTestCase:
    """A base testcase class for unit testing individual checker classes."""

    CHECKER_CLASS = None
    CONFIG = {}

    def setup_method(self):
        self.linter = UnittestLinter()
        self.checker = self.CHECKER_CLASS(self.linter)  # pylint: disable=not-callable
        for key, value in self.CONFIG.items():
            setattr(self.checker.config, key, value)
        self.checker.open()

    @contextlib.contextmanager
    def assertNoMessages(self):
        """Assert that no messages are added by the given method."""
        with self.assertAddsMessages():
            yield

    @contextlib.contextmanager
    def assertAddsMessages(self, *messages):
        """Assert that exactly the given method adds the given messages.

        The list of messages must exactly match *all* the messages added by the
        method. Additionally, we check to see whether the args in each message can
        actually be substituted into the message string.
        """
        yield
        got = self.linter.release_messages()
        msg = "Expected messages did not match actual.\n" "Expected:\n%s\nGot:\n%s" % (
            "\n".join(repr(m) for m in messages),
            "\n".join(repr(m) for m in got),
        )
        assert list(messages) == got, msg

    def walk(self, node):
        """recursive walk on the given node"""
        walker = ASTWalker(linter)
        walker.add_checker(self.checker)
        walker.walk(node)


# Init
test_reporter = TestReporter()
linter = PyLinter()
linter.set_reporter(test_reporter)
linter.config.persistent = 0
checkers.initialize(linter)


def _tokenize_str(code):
    return list(tokenize.generate_tokens(StringIO(code).readline))


@contextlib.contextmanager
def _create_tempfile(content=None):
    """Create a new temporary file.

    If *content* parameter is given, then it will be written
    in the temporary file, before passing it back.
    This is a context manager and should be used with a *with* statement.
    """
    # Can't use tempfile.NamedTemporaryFile here
    # because on Windows the file must be closed before writing to it,
    # see https://bugs.python.org/issue14243
    file_handle, tmp = tempfile.mkstemp()
    if content:
        # erff
        write(file_handle, bytes(content, "ascii"))
    try:
        yield tmp
    finally:
        close(file_handle)
        remove(tmp)


@contextlib.contextmanager
def _create_file_backed_module(code):
    """Create an astroid module for the given code, backed by a real file."""
    with _create_tempfile() as temp:
        module = astroid.parse(code)
        module.file = temp
        yield module


class NoFileError(Exception):
    pass


class OutputLine(
    collections.namedtuple(
        "OutputLine", ["symbol", "lineno", "object", "msg", "confidence"]
    )
):
    @classmethod
    def from_msg(cls, msg):
        return cls(
            msg.symbol,
            msg.line,
            msg.obj or "",
            msg.msg.replace("\r\n", "\n"),
            msg.confidence.name
            if msg.confidence != interfaces.UNDEFINED
            else interfaces.HIGH.name,
        )

    @classmethod
    def from_csv(cls, row):
        confidence = row[4] if len(row) == 5 else interfaces.HIGH.name
        return cls(row[0], int(row[1]), row[2], row[3], confidence)

    def to_csv(self):
        if self.confidence == interfaces.HIGH.name:
            return self[:-1]

        return self


# Common sub-expressions.
_MESSAGE = {"msg": r"[a-z][a-z\-]+"}
# Matches a #,
#  - followed by a comparison operator and a Python version (optional),
#  - followed by a line number with a +/- (optional),
#  - followed by a list of bracketed message symbols.
# Used to extract expected messages from testdata files.
_EXPECTED_RE = re.compile(
    r"\s*#\s*(?:(?P<line>[+-]?[0-9]+):)?"
    r"(?:(?P<op>[><=]+) *(?P<version>[0-9.]+):)?"
    r"\s*\[(?P<msgs>%(msg)s(?:,\s*%(msg)s)*)\]" % _MESSAGE
)


def parse_python_version(ver_str):
    return tuple(int(digit) for digit in ver_str.split("."))


class FunctionalTestReporter(BaseReporter):  # pylint: disable=abstract-method
    def handle_message(self, msg):
        self.messages.append(msg)

    def on_set_current_module(self, module, filepath):
        self.messages = []

    def display_reports(self, layout):
        """Ignore layouts and don't call self._display()."""


class FunctionalTestFile:
    """A single functional test case file with options."""

    _CONVERTERS = {
        "min_pyver": parse_python_version,
        "max_pyver": parse_python_version,
        "requires": lambda s: s.split(","),
    }

    def __init__(self, directory, filename):
        self._directory = directory
        self.base = filename.replace(".py", "")
        self.options = {
            "min_pyver": (2, 5),
            "max_pyver": (4, 0),
            "requires": [],
            "except_implementations": [],
            "exclude_platforms": [],
        }
        self._parse_options()

    def __repr__(self):
        return "FunctionalTest:{}".format(self.base)

    def _parse_options(self):
        cp = configparser.ConfigParser()
        cp.add_section("testoptions")
        try:
            cp.read(self.option_file)
        except NoFileError:
            pass

        for name, value in cp.items("testoptions"):
            conv = self._CONVERTERS.get(name, lambda v: v)
            self.options[name] = conv(value)

    @property
    def option_file(self):
        return self._file_type(".rc")

    @property
    def module(self):
        package = basename(self._directory)
        return ".".join([package, self.base])

    @property
    def expected_output(self):
        return self._file_type(".txt", check_exists=False)

    @property
    def source(self):
        return self._file_type(".py")

    def _file_type(self, ext, check_exists=True):
        name = join(self._directory, self.base + ext)
        if not check_exists or exists(name):
            return name
        raise NoFileError("Cannot find '{}'.".format(name))


_OPERATORS = {">": operator.gt, "<": operator.lt, ">=": operator.ge, "<=": operator.le}


def parse_expected_output(stream):
    return [OutputLine.from_csv(row) for row in csv.reader(stream, "test")]


def get_expected_messages(stream):
    """Parses a file and get expected messages.

    :param stream: File-like input stream.
    :type stream: enumerable
    :returns: A dict mapping line,msg-symbol tuples to the count on this line.
    :rtype: dict
    """
    messages = collections.Counter()
    for i, line in enumerate(stream):
        match = _EXPECTED_RE.search(line)
        if match is None:
            continue
        line = match.group("line")
        if line is None:
            line = i + 1
        elif line.startswith("+") or line.startswith("-"):
            line = i + 1 + int(line)
        else:
            line = int(line)

        version = match.group("version")
        op = match.group("op")
        if version:
            required = parse_python_version(version)
            if not _OPERATORS[op](sys.version_info, required):
                continue

        for msg_id in match.group("msgs").split(","):
            messages[line, msg_id.strip()] += 1
    return messages


def multiset_difference(left_op, right_op):
    """Takes two multisets and compares them.

    A multiset is a dict with the cardinality of the key as the value.

    :param left_op: The expected entries.
    :type left_op: set
    :param right_op: Actual entries.
    :type right_op: set

    :returns: The two multisets of missing and unexpected messages.
    :rtype: tuple
    """
    missing = left_op.copy()
    missing.subtract(right_op)
    unexpected = {}
    for key, value in list(missing.items()):
        if value <= 0:
            missing.pop(key)
            if value < 0:
                unexpected[key] = -value
    return missing, unexpected


class LintModuleTest:
    maxDiff = None

    def __init__(self, test_file):
        _test_reporter = FunctionalTestReporter()
        self._linter = PyLinter()
        self._linter.set_reporter(_test_reporter)
        self._linter.config.persistent = 0
        checkers.initialize(self._linter)
        self._linter.disable("I")
        try:
            self._linter.read_config_file(test_file.option_file)
            self._linter.load_config_file()
        except NoFileError:
            pass
        self._test_file = test_file

    def setUp(self):
        if self._should_be_skipped_due_to_version():
            pytest.skip(
                "Test cannot run with Python %s." % (sys.version.split(" ")[0],)
            )
        missing = []
        for req in self._test_file.options["requires"]:
            try:
                __import__(req)
            except ImportError:
                missing.append(req)
        if missing:
            pytest.skip("Requires %s to be present." % (",".join(missing),))
        if self._test_file.options["except_implementations"]:
            implementations = [
                item.strip()
                for item in self._test_file.options["except_implementations"].split(",")
            ]
            implementation = platform.python_implementation()
            if implementation in implementations:
                pytest.skip(
                    "Test cannot run with Python implementation %r" % (implementation,)
                )
        if self._test_file.options["exclude_platforms"]:
            platforms = [
                item.strip()
                for item in self._test_file.options["exclude_platforms"].split(",")
            ]
            if sys.platform.lower() in platforms:
                pytest.skip("Test cannot run on platform %r" % (sys.platform,))

    def _should_be_skipped_due_to_version(self):
        return (
            sys.version_info < self._test_file.options["min_pyver"]
            or sys.version_info > self._test_file.options["max_pyver"]
        )

    def __str__(self):
        return "%s (%s.%s)" % (
            self._test_file.base,
            self.__class__.__module__,
            self.__class__.__name__,
        )

    def _open_expected_file(self):
        return open(self._test_file.expected_output)

    def _open_source_file(self):
        if self._test_file.base == "invalid_encoded_data":
            return open(self._test_file.source)
        if "latin1" in self._test_file.base:
            return open(self._test_file.source, encoding="latin1")
        return open(self._test_file.source, encoding="utf8")

    def _get_expected(self):
        with self._open_source_file() as fobj:
            expected_msgs = get_expected_messages(fobj)

        if expected_msgs:
            with self._open_expected_file() as fobj:
                expected_output_lines = parse_expected_output(fobj)
        else:
            expected_output_lines = []
        return expected_msgs, expected_output_lines

    def _get_received(self):
        messages = self._linter.reporter.messages
        messages.sort(key=lambda m: (m.line, m.symbol, m.msg))
        received_msgs = collections.Counter()
        received_output_lines = []
        for msg in messages:
            assert (
                msg.symbol != "fatal"
            ), "Pylint analysis failed because of '{}'".format(msg.msg)
            received_msgs[msg.line, msg.symbol] += 1
            received_output_lines.append(OutputLine.from_msg(msg))
        return received_msgs, received_output_lines

    def _runTest(self):
        modules_to_check = [self._test_file.source]
        self._linter.check(modules_to_check)
        expected_messages, expected_text = self._get_expected()
        received_messages, received_text = self._get_received()

        if expected_messages != received_messages:
            msg = ['Wrong results for file "%s":' % (self._test_file.base)]
            missing, unexpected = multiset_difference(
                expected_messages, received_messages
            )
            if missing:
                msg.append("\nExpected in testdata:")
                msg.extend(" %3d: %s" % msg for msg in sorted(missing))
            if unexpected:
                msg.append("\nUnexpected in testdata:")
                msg.extend(" %3d: %s" % msg for msg in sorted(unexpected))
            pytest.fail("\n".join(msg))
        self._check_output_text(expected_messages, expected_text, received_text)

    @classmethod
    def _split_lines(cls, expected_messages, lines):
        emitted, omitted = [], []
        for msg in lines:
            if (msg[1], msg[0]) in expected_messages:
                emitted.append(msg)
            else:
                omitted.append(msg)
        return emitted, omitted

    def _check_output_text(self, expected_messages, expected_lines, received_lines):
        expected_lines = self._split_lines(expected_messages, expected_lines)[0]
        assert (
            expected_lines == received_lines
        ), "Expected test lines did not match for test: {}".format(self._test_file.base)
