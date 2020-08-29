# Licensed under the GPL: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
# For details: https://github.com/PyCQA/pylint/blob/master/COPYING

import collections
import contextlib
import functools
import operator
import os
import sys
import tokenize
import traceback
import warnings
from io import TextIOWrapper

import astroid
from astroid import modutils
from astroid.builder import AstroidBuilder

from pylint import checkers, config, exceptions, interfaces, reporters
from pylint.constants import MAIN_CHECKER_NAME, MSG_TYPES
from pylint.lint.check_parallel import check_parallel
from pylint.lint.report_functions import (
    report_messages_by_module_stats,
    report_messages_stats,
    report_total_messages_stats,
)
from pylint.lint.utils import fix_import_path
from pylint.message import MessageDefinitionStore, MessagesHandlerMixIn
from pylint.reporters.ureports import nodes as report_nodes
from pylint.utils import ASTWalker, FileState, utils
from pylint.utils.pragma_parser import (
    OPTION_PO,
    InvalidPragmaError,
    UnRecognizedOptionError,
    parse_pragma,
)

MANAGER = astroid.MANAGER


def _read_stdin():
    # https://mail.python.org/pipermail/python-list/2012-November/634424.html
    sys.stdin = TextIOWrapper(sys.stdin.detach(), encoding="utf-8")
    return sys.stdin.read()


# Python Linter class #########################################################

MSGS = {
    "F0001": (
        "%s",
        "fatal",
        "Used when an error occurred preventing the analysis of a \
              module (unable to find it for instance).",
    ),
    "F0002": (
        "%s: %s",
        "astroid-error",
        "Used when an unexpected error occurred while building the "
        "Astroid  representation. This is usually accompanied by a "
        "traceback. Please report such errors !",
    ),
    "F0010": (
        "error while code parsing: %s",
        "parse-error",
        "Used when an exception occurred while building the Astroid "
        "representation which could be handled by astroid.",
    ),
    "I0001": (
        "Unable to run raw checkers on built-in module %s",
        "raw-checker-failed",
        "Used to inform that a built-in module has not been checked "
        "using the raw checkers.",
    ),
    "I0010": (
        "Unable to consider inline option %r",
        "bad-inline-option",
        "Used when an inline option is either badly formatted or can't "
        "be used inside modules.",
    ),
    "I0011": (
        "Locally disabling %s (%s)",
        "locally-disabled",
        "Used when an inline option disables a message or a messages category.",
    ),
    "I0013": (
        "Ignoring entire file",
        "file-ignored",
        "Used to inform that the file will not be checked",
    ),
    "I0020": (
        "Suppressed %s (from line %d)",
        "suppressed-message",
        "A message was triggered on a line, but suppressed explicitly "
        "by a disable= comment in the file. This message is not "
        "generated for messages that are ignored due to configuration "
        "settings.",
    ),
    "I0021": (
        "Useless suppression of %s",
        "useless-suppression",
        "Reported when a message is explicitly disabled for a line or "
        "a block of code, but never triggered.",
    ),
    "I0022": (
        'Pragma "%s" is deprecated, use "%s" instead',
        "deprecated-pragma",
        "Some inline pylint options have been renamed or reworked, "
        "only the most recent form should be used. "
        "NOTE:skip-all is only available with pylint >= 0.26",
        {"old_names": [("I0014", "deprecated-disable-all")]},
    ),
    "E0001": ("%s", "syntax-error", "Used when a syntax error is raised for a module."),
    "E0011": (
        "Unrecognized file option %r",
        "unrecognized-inline-option",
        "Used when an unknown inline option is encountered.",
    ),
    "E0012": (
        "Bad option value %r",
        "bad-option-value",
        "Used when a bad value for an inline option is encountered.",
    ),
}


# pylint: disable=too-many-instance-attributes,too-many-public-methods
class PyLinter(
    config.OptionsManagerMixIn,
    MessagesHandlerMixIn,
    reporters.ReportsHandlerMixIn,
    checkers.BaseTokenChecker,
):
    """lint Python modules using external checkers.

    This is the main checker controlling the other ones and the reports
    generation. It is itself both a raw checker and an astroid checker in order
    to:
    * handle message activation / deactivation at the module level
    * handle some basic but necessary stats'data (number of classes, methods...)

    IDE plugin developers: you may have to call
    `astroid.builder.MANAGER.astroid_cache.clear()` across runs if you want
    to ensure the latest code version is actually checked.

    This class needs to support pickling for parallel linting to work. The exception
    is reporter member; see check_parallel function for more details.
    """

    __implements__ = (interfaces.ITokenChecker,)

    name = MAIN_CHECKER_NAME
    priority = 0
    level = 0
    msgs = MSGS

    @staticmethod
    def make_options():
        return (
            (
                "ignore",
                {
                    "type": "csv",
                    "metavar": "<file>[,<file>...]",
                    "dest": "black_list",
                    "default": ("CVS",),
                    "help": "Add files or directories to the blacklist. "
                    "They should be base names, not paths.",
                },
            ),
            (
                "ignore-patterns",
                {
                    "type": "regexp_csv",
                    "metavar": "<pattern>[,<pattern>...]",
                    "dest": "black_list_re",
                    "default": (),
                    "help": "Add files or directories matching the regex patterns to the"
                    " blacklist. The regex matches against base names, not paths.",
                },
            ),
            (
                "persistent",
                {
                    "default": True,
                    "type": "yn",
                    "metavar": "<y_or_n>",
                    "level": 1,
                    "help": "Pickle collected data for later comparisons.",
                },
            ),
            (
                "load-plugins",
                {
                    "type": "csv",
                    "metavar": "<modules>",
                    "default": (),
                    "level": 1,
                    "help": "List of plugins (as comma separated values of "
                    "python module names) to load, usually to register "
                    "additional checkers.",
                },
            ),
            (
                "output-format",
                {
                    "default": "text",
                    "type": "string",
                    "metavar": "<format>",
                    "short": "f",
                    "group": "Reports",
                    "help": "Set the output format. Available formats are text,"
                    " parseable, colorized, json and msvs (visual studio)."
                    " You can also give a reporter class, e.g. mypackage.mymodule."
                    "MyReporterClass.",
                },
            ),
            (
                "reports",
                {
                    "default": False,
                    "type": "yn",
                    "metavar": "<y_or_n>",
                    "short": "r",
                    "group": "Reports",
                    "help": "Tells whether to display a full report or only the "
                    "messages.",
                },
            ),
            (
                "evaluation",
                {
                    "type": "string",
                    "metavar": "<python_expression>",
                    "group": "Reports",
                    "level": 1,
                    "default": "10.0 - ((float(5 * error + warning + refactor + "
                    "convention) / statement) * 10)",
                    "help": "Python expression which should return a score less "
                    "than or equal to 10. You have access to the variables "
                    "'error', 'warning', 'refactor', and 'convention' which "
                    "contain the number of messages in each category, as well as "
                    "'statement' which is the total number of statements "
                    "analyzed. This score is used by the global "
                    "evaluation report (RP0004).",
                },
            ),
            (
                "score",
                {
                    "default": True,
                    "type": "yn",
                    "metavar": "<y_or_n>",
                    "short": "s",
                    "group": "Reports",
                    "help": "Activate the evaluation score.",
                },
            ),
            (
                "fail-under",
                {
                    "default": 10,
                    "type": "float",
                    "metavar": "<score>",
                    "help": "Specify a score threshold to be exceeded before program exits with error.",
                },
            ),
            (
                "confidence",
                {
                    "type": "multiple_choice",
                    "metavar": "<levels>",
                    "default": "",
                    "choices": [c.name for c in interfaces.CONFIDENCE_LEVELS],
                    "group": "Messages control",
                    "help": "Only show warnings with the listed confidence levels."
                    " Leave empty to show all. Valid levels: %s."
                    % (", ".join(c.name for c in interfaces.CONFIDENCE_LEVELS),),
                },
            ),
            (
                "enable",
                {
                    "type": "csv",
                    "metavar": "<msg ids>",
                    "short": "e",
                    "group": "Messages control",
                    "help": "Enable the message, report, category or checker with the "
                    "given id(s). You can either give multiple identifier "
                    "separated by comma (,) or put this option multiple time "
                    "(only on the command line, not in the configuration file "
                    "where it should appear only once). "
                    'See also the "--disable" option for examples.',
                },
            ),
            (
                "disable",
                {
                    "type": "csv",
                    "metavar": "<msg ids>",
                    "short": "d",
                    "group": "Messages control",
                    "help": "Disable the message, report, category or checker "
                    "with the given id(s). You can either give multiple identifiers "
                    "separated by comma (,) or put this option multiple times "
                    "(only on the command line, not in the configuration file "
                    "where it should appear only once). "
                    'You can also use "--disable=all" to disable everything first '
                    "and then reenable specific checks. For example, if you want "
                    "to run only the similarities checker, you can use "
                    '"--disable=all --enable=similarities". '
                    "If you want to run only the classes checker, but have no "
                    "Warning level messages displayed, use "
                    '"--disable=all --enable=classes --disable=W".',
                },
            ),
            (
                "msg-template",
                {
                    "type": "string",
                    "metavar": "<template>",
                    "group": "Reports",
                    "help": (
                        "Template used to display messages. "
                        "This is a python new-style format string "
                        "used to format the message information. "
                        "See doc for all details."
                    ),
                },
            ),
            (
                "jobs",
                {
                    "type": "int",
                    "metavar": "<n-processes>",
                    "short": "j",
                    "default": 1,
                    "help": "Use multiple processes to speed up Pylint. Specifying 0 will "
                    "auto-detect the number of processors available to use.",
                },
            ),
            (
                "unsafe-load-any-extension",
                {
                    "type": "yn",
                    "metavar": "<yn>",
                    "default": False,
                    "hide": True,
                    "help": (
                        "Allow loading of arbitrary C extensions. Extensions"
                        " are imported into the active Python interpreter and"
                        " may run arbitrary code."
                    ),
                },
            ),
            (
                "limit-inference-results",
                {
                    "type": "int",
                    "metavar": "<number-of-results>",
                    "default": 100,
                    "help": (
                        "Control the amount of potential inferred values when inferring "
                        "a single object. This can help the performance when dealing with "
                        "large functions or complex, nested conditions. "
                    ),
                },
            ),
            (
                "extension-pkg-whitelist",
                {
                    "type": "csv",
                    "metavar": "<pkg[,pkg]>",
                    "default": [],
                    "help": (
                        "A comma-separated list of package or module names"
                        " from where C extensions may be loaded. Extensions are"
                        " loading into the active Python interpreter and may run"
                        " arbitrary code."
                    ),
                },
            ),
            (
                "suggestion-mode",
                {
                    "type": "yn",
                    "metavar": "<yn>",
                    "default": True,
                    "help": (
                        "When enabled, pylint would attempt to guess common "
                        "misconfiguration and emit user-friendly hints instead "
                        "of false-positive error messages."
                    ),
                },
            ),
            (
                "exit-zero",
                {
                    "action": "store_true",
                    "help": (
                        "Always return a 0 (non-error) status code, even if "
                        "lint errors are found. This is primarily useful in "
                        "continuous integration scripts."
                    ),
                },
            ),
            (
                "from-stdin",
                {
                    "action": "store_true",
                    "help": (
                        "Interpret the stdin as a python script, whose filename "
                        "needs to be passed as the module_or_package argument."
                    ),
                },
            ),
        )

    option_groups = (
        ("Messages control", "Options controlling analysis messages"),
        ("Reports", "Options related to output formatting and reporting"),
    )

    def __init__(self, options=(), reporter=None, option_groups=(), pylintrc=None):
        # some stuff has to be done before ancestors initialization...
        #
        # messages store / checkers / reporter / astroid manager
        self.msgs_store = MessageDefinitionStore()
        self.reporter = None
        self._reporter_name = None
        self._reporters = {}
        self._checkers = collections.defaultdict(list)
        self._pragma_lineno = {}
        self._ignore_file = False
        # visit variables
        self.file_state = FileState()
        self.current_name = None
        self.current_file = None
        self.stats = None
        # init options
        self._external_opts = options
        self.options = options + PyLinter.make_options()
        self.option_groups = option_groups + PyLinter.option_groups
        self._options_methods = {"enable": self.enable, "disable": self.disable}
        self._bw_options_methods = {
            "disable-msg": self.disable,
            "enable-msg": self.enable,
        }
        MessagesHandlerMixIn.__init__(self)
        reporters.ReportsHandlerMixIn.__init__(self)
        super().__init__(
            usage=__doc__,
            config_file=pylintrc or next(config.find_default_config_files(), None),
        )
        checkers.BaseTokenChecker.__init__(self)
        # provided reports
        self.reports = (
            ("RP0001", "Messages by category", report_total_messages_stats),
            (
                "RP0002",
                "% errors / warnings by module",
                report_messages_by_module_stats,
            ),
            ("RP0003", "Messages", report_messages_stats),
        )
        self.register_checker(self)
        self._dynamic_plugins = set()
        self._python3_porting_mode = False
        self._error_mode = False
        self.load_provider_defaults()
        if reporter:
            self.set_reporter(reporter)

    def load_default_plugins(self):
        checkers.initialize(self)
        reporters.initialize(self)
        # Make sure to load the default reporter, because
        # the option has been set before the plugins had been loaded.
        if not self.reporter:
            self._load_reporter()

    def load_plugin_modules(self, modnames):
        """take a list of module names which are pylint plugins and load
        and register them
        """
        for modname in modnames:
            if modname in self._dynamic_plugins:
                continue
            self._dynamic_plugins.add(modname)
            module = modutils.load_module_from_name(modname)
            module.register(self)

    def load_plugin_configuration(self):
        """Call the configuration hook for plugins

        This walks through the list of plugins, grabs the "load_configuration"
        hook, if exposed, and calls it to allow plugins to configure specific
        settings.
        """
        for modname in self._dynamic_plugins:
            module = modutils.load_module_from_name(modname)
            if hasattr(module, "load_configuration"):
                module.load_configuration(self)

    def _load_reporter(self):
        name = self._reporter_name.lower()
        if name in self._reporters:
            self.set_reporter(self._reporters[name]())
        else:
            try:
                reporter_class = self._load_reporter_class()
            except (ImportError, AttributeError) as e:
                raise exceptions.InvalidReporterError(name) from e
            else:
                self.set_reporter(reporter_class())

    def _load_reporter_class(self):
        qname = self._reporter_name
        module = modutils.load_module_from_name(modutils.get_module_part(qname))
        class_name = qname.split(".")[-1]
        reporter_class = getattr(module, class_name)
        return reporter_class

    def set_reporter(self, reporter):
        """set the reporter used to display messages and reports"""
        self.reporter = reporter
        reporter.linter = self

    def set_option(self, optname, value, action=None, optdict=None):
        """overridden from config.OptionsProviderMixin to handle some
        special options
        """
        if optname in self._options_methods or optname in self._bw_options_methods:
            if value:
                try:
                    meth = self._options_methods[optname]
                except KeyError:
                    meth = self._bw_options_methods[optname]
                    warnings.warn(
                        "%s is deprecated, replace it by %s"
                        % (optname, optname.split("-")[0]),
                        DeprecationWarning,
                    )
                value = utils._check_csv(value)
                if isinstance(value, (list, tuple)):
                    for _id in value:
                        meth(_id, ignore_unknown=True)
                else:
                    meth(value)
                return  # no need to call set_option, disable/enable methods do it
        elif optname == "output-format":
            self._reporter_name = value
            # If the reporters are already available, load
            # the reporter class.
            if self._reporters:
                self._load_reporter()

        try:
            checkers.BaseTokenChecker.set_option(self, optname, value, action, optdict)
        except config.UnsupportedAction:
            print("option %s can't be read from config file" % optname, file=sys.stderr)

    def register_reporter(self, reporter_class):
        self._reporters[reporter_class.name] = reporter_class

    def report_order(self):
        reports = sorted(self._reports, key=lambda x: getattr(x, "name", ""))
        try:
            # Remove the current reporter and add it
            # at the end of the list.
            reports.pop(reports.index(self))
        except ValueError:
            pass
        else:
            reports.append(self)
        return reports

    # checkers manipulation methods ############################################

    def register_checker(self, checker):
        """register a new checker

        checker is an object implementing IRawChecker or / and IAstroidChecker
        """
        assert checker.priority <= 0, "checker priority can't be >= 0"
        self._checkers[checker.name].append(checker)
        for r_id, r_title, r_cb in checker.reports:
            self.register_report(r_id, r_title, r_cb, checker)
        self.register_options_provider(checker)
        if hasattr(checker, "msgs"):
            self.msgs_store.register_messages_from_checker(checker)
        checker.load_defaults()

        # Register the checker, but disable all of its messages.
        if not getattr(checker, "enabled", True):
            self.disable(checker.name)

    def disable_noerror_messages(self):
        for msgcat, msgids in self.msgs_store._msgs_by_category.items():
            # enable only messages with 'error' severity and above ('fatal')
            if msgcat in ["E", "F"]:
                for msgid in msgids:
                    self.enable(msgid)
            else:
                for msgid in msgids:
                    self.disable(msgid)

    def disable_reporters(self):
        """disable all reporters"""
        for _reporters in self._reports.values():
            for report_id, _, _ in _reporters:
                self.disable_report(report_id)

    def error_mode(self):
        """error mode: enable only errors; no reports, no persistent"""
        self._error_mode = True
        self.disable_noerror_messages()
        self.disable("miscellaneous")
        if self._python3_porting_mode:
            self.disable("all")
            for msg_id in self._checker_messages("python3"):
                if msg_id.startswith("E"):
                    self.enable(msg_id)
            config_parser = self.cfgfile_parser
            if config_parser.has_option("MESSAGES CONTROL", "disable"):
                value = config_parser.get("MESSAGES CONTROL", "disable")
                self.global_set_option("disable", value)
        else:
            self.disable("python3")
        self.set_option("reports", False)
        self.set_option("persistent", False)
        self.set_option("score", False)

    def python3_porting_mode(self):
        """Disable all other checkers and enable Python 3 warnings."""
        self.disable("all")
        # re-enable some errors, or 'print', 'raise', 'async', 'await' will mistakenly lint fine
        self.enable("fatal")  # F0001
        self.enable("astroid-error")  # F0002
        self.enable("parse-error")  # F0010
        self.enable("syntax-error")  # E0001
        self.enable("python3")
        if self._error_mode:
            # The error mode was activated, using the -E flag.
            # So we'll need to enable only the errors from the
            # Python 3 porting checker.
            for msg_id in self._checker_messages("python3"):
                if msg_id.startswith("E"):
                    self.enable(msg_id)
                else:
                    self.disable(msg_id)
        config_parser = self.cfgfile_parser
        if config_parser.has_option("MESSAGES CONTROL", "disable"):
            value = config_parser.get("MESSAGES CONTROL", "disable")
            self.global_set_option("disable", value)
        self._python3_porting_mode = True

    def list_messages_enabled(self):
        enabled = [
            "  %s (%s)" % (message.symbol, message.msgid)
            for message in self.msgs_store.messages
            if self.is_message_enabled(message.msgid)
        ]
        disabled = [
            "  %s (%s)" % (message.symbol, message.msgid)
            for message in self.msgs_store.messages
            if not self.is_message_enabled(message.msgid)
        ]
        print("Enabled messages:")
        for msg in sorted(enabled):
            print(msg)
        print("\nDisabled messages:")
        for msg in sorted(disabled):
            print(msg)
        print("")

    # block level option handling #############################################
    #
    # see func_block_disable_msg.py test case for expected behaviour

    def process_tokens(self, tokens):
        """process tokens from the current module to search for module/block
        level options
        """
        control_pragmas = {"disable", "enable"}
        prev_line = None
        saw_newline = True
        seen_newline = True
        for (tok_type, content, start, _, _) in tokens:
            if prev_line and prev_line != start[0]:
                saw_newline = seen_newline
                seen_newline = False

            prev_line = start[0]
            if tok_type in (tokenize.NL, tokenize.NEWLINE):
                seen_newline = True

            if tok_type != tokenize.COMMENT:
                continue
            match = OPTION_PO.search(content)
            if match is None:
                continue

            try:
                for pragma_repr in parse_pragma(match.group(2)):
                    if pragma_repr.action in ("disable-all", "skip-file"):
                        if pragma_repr.action == "disable-all":
                            self.add_message(
                                "deprecated-pragma",
                                line=start[0],
                                args=("disable-all", "skip-file"),
                            )
                        self.add_message("file-ignored", line=start[0])
                        self._ignore_file = True
                        return
                    try:
                        meth = self._options_methods[pragma_repr.action]
                    except KeyError:
                        meth = self._bw_options_methods[pragma_repr.action]
                        # found a "(dis|en)able-msg" pragma deprecated suppression
                        self.add_message(
                            "deprecated-pragma",
                            line=start[0],
                            args=(
                                pragma_repr.action,
                                pragma_repr.action.replace("-msg", ""),
                            ),
                        )
                    for msgid in pragma_repr.messages:
                        # Add the line where a control pragma was encountered.
                        if pragma_repr.action in control_pragmas:
                            self._pragma_lineno[msgid] = start[0]

                        if (pragma_repr.action, msgid) == ("disable", "all"):
                            self.add_message(
                                "deprecated-pragma",
                                line=start[0],
                                args=("disable=all", "skip-file"),
                            )
                            self.add_message("file-ignored", line=start[0])
                            self._ignore_file = True
                            return
                            # If we did not see a newline between the previous line and now,
                            # we saw a backslash so treat the two lines as one.
                        l_start = start[0]
                        if not saw_newline:
                            l_start -= 1
                        try:
                            meth(msgid, "module", l_start)
                        except exceptions.UnknownMessageError:
                            self.add_message(
                                "bad-option-value", args=msgid, line=start[0]
                            )
            except UnRecognizedOptionError as err:
                self.add_message(
                    "unrecognized-inline-option", args=err.token, line=start[0]
                )
                continue
            except InvalidPragmaError as err:
                self.add_message("bad-inline-option", args=err.token, line=start[0])
                continue

    # code checking methods ###################################################

    def get_checkers(self):
        """return all available checkers as a list"""
        return [self] + [
            c
            for _checkers in self._checkers.values()
            for c in _checkers
            if c is not self
        ]

    def get_checker_names(self):
        """Get all the checker names that this linter knows about."""
        current_checkers = self.get_checkers()
        return sorted(
            {
                checker.name
                for checker in current_checkers
                if checker.name != MAIN_CHECKER_NAME
            }
        )

    def prepare_checkers(self):
        """return checkers needed for activated messages and reports"""
        if not self.config.reports:
            self.disable_reporters()
        # get needed checkers
        needed_checkers = [self]
        for checker in self.get_checkers()[1:]:
            messages = {msg for msg in checker.msgs if self.is_message_enabled(msg)}
            if messages or any(self.report_is_enabled(r[0]) for r in checker.reports):
                needed_checkers.append(checker)
        # Sort checkers by priority
        needed_checkers = sorted(
            needed_checkers, key=operator.attrgetter("priority"), reverse=True
        )
        return needed_checkers

    # pylint: disable=unused-argument
    @staticmethod
    def should_analyze_file(modname, path, is_argument=False):
        """Returns whether or not a module should be checked.

        This implementation returns True for all python source file, indicating
        that all files should be linted.

        Subclasses may override this method to indicate that modules satisfying
        certain conditions should not be linted.

        :param str modname: The name of the module to be checked.
        :param str path: The full path to the source code of the module.
        :param bool is_argument: Whetter the file is an argument to pylint or not.
                                 Files which respect this property are always
                                 checked, since the user requested it explicitly.
        :returns: True if the module should be checked.
        :rtype: bool
        """
        if is_argument:
            return True
        return path.endswith(".py")

    # pylint: enable=unused-argument

    def initialize(self):
        """Initialize linter for linting

        This method is called before any linting is done.
        """
        # initialize msgs_state now that all messages have been registered into
        # the store
        for msg in self.msgs_store.messages:
            if not msg.may_be_emitted():
                self._msgs_state[msg.msgid] = False

    def check(self, files_or_modules):
        """main checking entry: check a list of files or modules from their name.

        files_or_modules is either a string or list of strings presenting modules to check.
        """

        self.initialize()

        if not isinstance(files_or_modules, (list, tuple)):
            files_or_modules = (files_or_modules,)

        if self.config.from_stdin:
            if len(files_or_modules) != 1:
                raise exceptions.InvalidArgsError(
                    "Missing filename required for --from-stdin"
                )

            filepath = files_or_modules[0]
            with fix_import_path(files_or_modules):
                self._check_files(
                    functools.partial(self.get_ast, data=_read_stdin()),
                    [self._get_file_descr_from_stdin(filepath)],
                )
        elif self.config.jobs == 1:
            with fix_import_path(files_or_modules):
                self._check_files(
                    self.get_ast, self._iterate_file_descrs(files_or_modules)
                )
        else:
            check_parallel(
                self,
                self.config.jobs,
                self._iterate_file_descrs(files_or_modules),
                files_or_modules,
            )

    def check_single_file(self, name, filepath, modname):
        """Check single file

        The arguments are the same that are documented in _check_files

        The initialize() method should be called before calling this method
        """
        with self._astroid_module_checker() as check_astroid_module:
            self._check_file(
                self.get_ast, check_astroid_module, name, filepath, modname
            )

    def _check_files(self, get_ast, file_descrs):
        """Check all files from file_descrs

        The file_descrs should be iterable of tuple (name, filepath, modname)
        where
        - name: full name of the module
        - filepath: path of the file
        - modname: module name
        """
        with self._astroid_module_checker() as check_astroid_module:
            for name, filepath, modname in file_descrs:
                self._check_file(get_ast, check_astroid_module, name, filepath, modname)

    def _check_file(self, get_ast, check_astroid_module, name, filepath, modname):
        """Check a file using the passed utility functions (get_ast and check_astroid_module)

        :param callable get_ast: callable returning AST from defined file taking the following arguments
        - filepath: path to the file to check
        - name: Python module name
        :param callable check_astroid_module: callable checking an AST taking the following arguments
        - ast: AST of the module
        :param str name: full name of the module
        :param str filepath: path to checked file
        :param str modname: name of the checked Python module
        """
        self.set_current_module(name, filepath)
        # get the module representation
        ast_node = get_ast(filepath, name)
        if ast_node is None:
            return

        self._ignore_file = False

        self.file_state = FileState(modname)
        # fix the current file (if the source file was not available or
        # if it's actually a c extension)
        self.current_file = ast_node.file  # pylint: disable=maybe-no-member
        check_astroid_module(ast_node)
        # warn about spurious inline messages handling
        spurious_messages = self.file_state.iter_spurious_suppression_messages(
            self.msgs_store
        )
        for msgid, line, args in spurious_messages:
            self.add_message(msgid, line, None, args)

    @staticmethod
    def _get_file_descr_from_stdin(filepath):
        """Return file description (tuple of module name, file path, base name) from given file path

        This method is used for creating suitable file description for _check_files when the
        source is standard input.
        """
        try:
            # Note that this function does not really perform an
            # __import__ but may raise an ImportError exception, which
            # we want to catch here.
            modname = ".".join(modutils.modpath_from_file(filepath))
        except ImportError:
            modname = os.path.splitext(os.path.basename(filepath))[0]

        return (modname, filepath, filepath)

    def _iterate_file_descrs(self, files_or_modules):
        """Return generator yielding file descriptions (tuples of module name, file path, base name)

        The returned generator yield one item for each Python module that should be linted.
        """
        for descr in self._expand_files(files_or_modules):
            name, filepath, is_arg = descr["name"], descr["path"], descr["isarg"]
            if self.should_analyze_file(name, filepath, is_argument=is_arg):
                yield (name, filepath, descr["basename"])

    def _expand_files(self, modules):
        """get modules and errors from a list of modules and handle errors
        """
        result, errors = utils.expand_modules(
            modules, self.config.black_list, self.config.black_list_re
        )
        for error in errors:
            message = modname = error["mod"]
            key = error["key"]
            self.set_current_module(modname)
            if key == "fatal":
                message = str(error["ex"]).replace(os.getcwd() + os.sep, "")
            self.add_message(key, args=message)
        return result

    def set_current_module(self, modname, filepath=None):
        """set the name of the currently analyzed module and
        init statistics for it
        """
        if not modname and filepath is None:
            return
        self.reporter.on_set_current_module(modname, filepath)
        self.current_name = modname
        self.current_file = filepath or modname
        self.stats["by_module"][modname] = {}
        self.stats["by_module"][modname]["statement"] = 0
        for msg_cat in MSG_TYPES.values():
            self.stats["by_module"][modname][msg_cat] = 0

    @contextlib.contextmanager
    def _astroid_module_checker(self):
        """Context manager for checking ASTs

        The value in the context is callable accepting AST as its only argument.
        """
        walker = ASTWalker(self)
        _checkers = self.prepare_checkers()
        tokencheckers = [
            c
            for c in _checkers
            if interfaces.implements(c, interfaces.ITokenChecker) and c is not self
        ]
        rawcheckers = [
            c for c in _checkers if interfaces.implements(c, interfaces.IRawChecker)
        ]
        # notify global begin
        for checker in _checkers:
            checker.open()
            if interfaces.implements(checker, interfaces.IAstroidChecker):
                walker.add_checker(checker)

        yield functools.partial(
            self.check_astroid_module,
            walker=walker,
            tokencheckers=tokencheckers,
            rawcheckers=rawcheckers,
        )

        # notify global end
        self.stats["statement"] = walker.nbstatements
        for checker in reversed(_checkers):
            checker.close()

    def get_ast(self, filepath, modname, data=None):
        """Return an ast(roid) representation of a module or a string.

        :param str filepath: path to checked file.
        :param str modname: The name of the module to be checked.
        :param str data: optional contents of the checked file.
        :returns: the AST
        :rtype: astroid.nodes.Module
        """
        try:
            if data is None:
                return MANAGER.ast_from_file(filepath, modname, source=True)
            return AstroidBuilder(MANAGER).string_build(data, modname, filepath)
        except astroid.AstroidSyntaxError as ex:
            # pylint: disable=no-member
            self.add_message(
                "syntax-error",
                line=getattr(ex.error, "lineno", 0),
                col_offset=getattr(ex.error, "offset", None),
                args=str(ex.error),
            )
        except astroid.AstroidBuildingException as ex:
            self.add_message("parse-error", args=ex)
        except Exception as ex:  # pylint: disable=broad-except
            traceback.print_exc()
            self.add_message("astroid-error", args=(ex.__class__, ex))

    def check_astroid_module(self, ast_node, walker, rawcheckers, tokencheckers):
        """Check a module from its astroid representation.

        For return value see _check_astroid_module
        """
        before_check_statements = walker.nbstatements

        retval = self._check_astroid_module(
            ast_node, walker, rawcheckers, tokencheckers
        )

        self.stats["by_module"][self.current_name]["statement"] = (
            walker.nbstatements - before_check_statements
        )

        return retval

    def _check_astroid_module(self, ast_node, walker, rawcheckers, tokencheckers):
        """Check given AST node with given walker and checkers

        :param astroid.nodes.Module ast_node: AST node of the module to check
        :param pylint.utils.ast_walker.ASTWalker walker: AST walker
        :param list rawcheckers: List of token checkers to use
        :param list tokencheckers: List of raw checkers to use

        :returns: True if the module was checked, False if ignored,
            None if the module contents could not be parsed
        :rtype: bool
        """
        try:
            tokens = utils.tokenize_module(ast_node)
        except tokenize.TokenError as ex:
            self.add_message("syntax-error", line=ex.args[1][0], args=ex.args[0])
            return None

        if not ast_node.pure_python:
            self.add_message("raw-checker-failed", args=ast_node.name)
        else:
            # assert astroid.file.endswith('.py')
            # invoke ITokenChecker interface on self to fetch module/block
            # level options
            self.process_tokens(tokens)
            if self._ignore_file:
                return False
            # walk ast to collect line numbers
            self.file_state.collect_block_lines(self.msgs_store, ast_node)
            # run raw and tokens checkers
            for checker in rawcheckers:
                checker.process_module(ast_node)
            for checker in tokencheckers:
                checker.process_tokens(tokens)
        # generate events to astroid checkers
        walker.walk(ast_node)
        return True

    # IAstroidChecker interface #################################################

    def open(self):
        """initialize counters"""
        self.stats = {"by_module": {}, "by_msg": {}}
        MANAGER.always_load_extensions = self.config.unsafe_load_any_extension
        MANAGER.max_inferable_values = self.config.limit_inference_results
        MANAGER.extension_package_whitelist.update(self.config.extension_pkg_whitelist)
        for msg_cat in MSG_TYPES.values():
            self.stats[msg_cat] = 0

    def generate_reports(self):
        """close the whole package /module, it's time to make reports !

        if persistent run, pickle results for later comparison
        """
        # Display whatever messages are left on the reporter.
        self.reporter.display_messages(report_nodes.Section())

        if self.file_state.base_name is not None:
            # load previous results if any
            previous_stats = config.load_results(self.file_state.base_name)
            self.reporter.on_close(self.stats, previous_stats)
            if self.config.reports:
                sect = self.make_reports(self.stats, previous_stats)
            else:
                sect = report_nodes.Section()

            if self.config.reports:
                self.reporter.display_reports(sect)
            score_value = self._report_evaluation()
            # save results if persistent run
            if self.config.persistent:
                config.save_results(self.stats, self.file_state.base_name)
        else:
            self.reporter.on_close(self.stats, {})
            score_value = None
        return score_value

    def _report_evaluation(self):
        """make the global evaluation report"""
        # check with at least check 1 statements (usually 0 when there is a
        # syntax error preventing pylint from further processing)
        note = None
        previous_stats = config.load_results(self.file_state.base_name)
        if self.stats["statement"] == 0:
            return note

        # get a global note for the code
        evaluation = self.config.evaluation
        try:
            note = eval(evaluation, {}, self.stats)  # pylint: disable=eval-used
        except Exception as ex:  # pylint: disable=broad-except
            msg = "An exception occurred while rating: %s" % ex
        else:
            self.stats["global_note"] = note
            msg = "Your code has been rated at %.2f/10" % note
            pnote = previous_stats.get("global_note")
            if pnote is not None:
                msg += " (previous run: %.2f/10, %+.2f)" % (pnote, note - pnote)

        if self.config.score:
            sect = report_nodes.EvaluationSection(msg)
            self.reporter.display_reports(sect)
        return note
