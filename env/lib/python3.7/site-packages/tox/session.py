"""
Automatically package and test a Python project against configurable
Python2 and Python3 based virtual environments. Environments are
setup by using virtualenv. Configuration is generally done through an
INI-style "tox.ini" file.
"""
from __future__ import print_function

import os
import pipes
import re
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager

import pkg_resources
import py

import tox
from tox.config import parseconfig
from tox.result import ResultLog
from tox.util import set_os_env_var
from tox.venv import VirtualEnv


def prepare(args):
    config = parseconfig(args)
    if config.option.help:
        show_help(config)
        raise SystemExit(0)
    elif config.option.helpini:
        show_help_ini(config)
        raise SystemExit(0)
    return config


def cmdline(args=None):
    if args is None:
        args = sys.argv[1:]
    main(args)


def main(args):
    try:
        config = prepare(args)
        with set_os_env_var("TOX_WORK_DIR", config.toxworkdir):
            retcode = build_session(config).runcommand()
        if retcode is None:
            retcode = 0
        raise SystemExit(retcode)
    except KeyboardInterrupt:
        raise SystemExit(2)
    except (tox.exception.MinVersionError, tox.exception.MissingRequirement) as e:
        r = Reporter(None)
        r.error(str(e))
        raise SystemExit(1)


def build_session(config):
    return Session(config)


def show_help(config):
    tw = py.io.TerminalWriter()
    tw.write(config._parser._format_help())
    tw.line()
    tw.line("Environment variables", bold=True)
    tw.line("TOXENV: comma separated list of environments (overridable by '-e')")
    tw.line("TOX_SKIP_ENV: regular expression to filter down from running tox environments")
    tw.line(
        "TOX_TESTENV_PASSENV: space-separated list of extra environment variables to be "
        "passed into test command environments"
    )
    tw.line("PY_COLORS: 0 disable colorized output, 1 enable (default)")


def show_help_ini(config):
    tw = py.io.TerminalWriter()
    tw.sep("-", "per-testenv attributes")
    for env_attr in config._testenv_attr:
        tw.line(
            "{:<15} {:<8} default: {}".format(
                env_attr.name, "<{}>".format(env_attr.type), env_attr.default
            ),
            bold=True,
        )
        tw.line(env_attr.help)
        tw.line()


class Action(object):
    def __init__(self, session, venv, msg, args):
        self.venv = venv
        self.msg = msg
        self.activity = msg.split(" ", 1)[0]
        self.session = session
        self.report = session.report
        self.args = args
        self.id = venv and venv.envconfig.envname or "tox"
        self._popenlist = []
        if self.venv:
            self.venvname = self.venv.name
        else:
            self.venvname = "GLOB"
        if msg == "runtests":
            cat = "test"
        else:
            cat = "setup"
        envlog = session.resultlog.get_envlog(self.venvname)
        self.commandlog = envlog.get_commandlog(cat)

    def __enter__(self):
        self.report.logaction_start(self)
        return self

    def __exit__(self, *args):
        self.report.logaction_finish(self)

    def setactivity(self, name, msg):
        self.activity = name
        if msg:
            self.report.verbosity0("{} {}: {}".format(self.venvname, name, msg), bold=True)
        else:
            self.report.verbosity1("{} {}: {}".format(self.venvname, name, msg), bold=True)

    def info(self, name, msg):
        self.report.verbosity1("{} {}: {}".format(self.venvname, name, msg), bold=True)

    def _initlogpath(self, actionid):
        if self.venv:
            logdir = self.venv.envconfig.envlogdir
        else:
            logdir = self.session.config.logdir
        try:
            log_count = len(logdir.listdir("{}-*".format(actionid)))
        except (py.error.ENOENT, py.error.ENOTDIR):
            logdir.ensure(dir=1)
            log_count = 0
        path = logdir.join("{}-{}.log".format(actionid, log_count))
        f = path.open("w")
        f.flush()
        return f

    def popen(self, args, cwd=None, env=None, redirect=True, returnout=False, ignore_ret=False):
        stdout = outpath = None
        resultjson = self.session.config.option.resultjson

        cmd_args = [str(x) for x in args]
        cmd_args_shell = " ".join(pipes.quote(i) for i in cmd_args)
        if resultjson or redirect:
            fout = self._initlogpath(self.id)
            fout.write(
                "actionid: {}\nmsg: {}\ncmdargs: {!r}\n\n".format(
                    self.id, self.msg, cmd_args_shell
                )
            )
            fout.flush()
            outpath = py.path.local(fout.name)
            fin = outpath.open("rb")
            fin.read()  # read the header, so it won't be written to stdout
            stdout = fout
        elif returnout:
            stdout = subprocess.PIPE
        if cwd is None:
            # FIXME XXX cwd = self.session.config.cwd
            cwd = py.path.local()
        try:
            popen = self._popen(args, cwd, env=env, stdout=stdout, stderr=subprocess.STDOUT)
        except OSError as e:
            self.report.error(
                "invocation failed (errno {:d}), args: {}, cwd: {}".format(
                    e.errno, cmd_args_shell, cwd
                )
            )
            raise
        popen.outpath = outpath
        popen.args = cmd_args
        popen.cwd = cwd
        popen.action = self
        self._popenlist.append(popen)
        try:
            self.report.logpopen(popen, cmd_args_shell)
            try:
                if resultjson and not redirect:
                    if popen.stderr is not None:
                        # prevent deadlock
                        raise ValueError("stderr must not be piped here")
                    # we read binary from the process and must write using a
                    # binary stream
                    buf = getattr(sys.stdout, "buffer", sys.stdout)
                    out = None
                    last_time = time.time()
                    while 1:
                        # we have to read one byte at a time, otherwise there
                        # might be no output for a long time with slow tests
                        data = fin.read(1)
                        if data:
                            buf.write(data)
                            if b"\n" in data or (time.time() - last_time) > 1:
                                # we flush on newlines or after 1 second to
                                # provide quick enough feedback to the user
                                # when printing a dot per test
                                buf.flush()
                                last_time = time.time()
                        elif popen.poll() is not None:
                            if popen.stdout is not None:
                                popen.stdout.close()
                            break
                        else:
                            time.sleep(0.1)
                            # the seek updates internal read buffers
                            fin.seek(0, 1)
                    fin.close()
                else:
                    out, err = popen.communicate()
            except KeyboardInterrupt:
                self.report.keyboard_interrupt()
                popen.wait()
                raise
            ret = popen.wait()
        finally:
            self._popenlist.remove(popen)
        if ret and not ignore_ret:
            invoked = " ".join(map(str, popen.args))
            if outpath:
                self.report.error(
                    "invocation failed (exit code {:d}), logfile: {}".format(ret, outpath)
                )
                out = outpath.read()
                self.report.error(out)
                if hasattr(self, "commandlog"):
                    self.commandlog.add_command(popen.args, out, ret)
                raise tox.exception.InvocationError("{} (see {})".format(invoked, outpath), ret)
            else:
                raise tox.exception.InvocationError("{!r}".format(invoked), ret)
        if not out and outpath:
            out = outpath.read()
        if hasattr(self, "commandlog"):
            self.commandlog.add_command(popen.args, out, ret)
        return out

    def _rewriteargs(self, cwd, args):
        newargs = []
        for arg in args:
            if not tox.INFO.IS_WIN and isinstance(arg, py.path.local):
                arg = cwd.bestrelpath(arg)
            newargs.append(str(arg))
        # subprocess does not always take kindly to .py scripts so adding the interpreter here
        if tox.INFO.IS_WIN:
            ext = os.path.splitext(str(newargs[0]))[1].lower()
            if ext == ".py" and self.venv:
                newargs = [str(self.venv.envconfig.envpython)] + newargs
        return newargs

    def _popen(self, args, cwd, stdout, stderr, env=None):
        if env is None:
            env = os.environ.copy()
        return self.session.popen(
            self._rewriteargs(cwd, args),
            shell=False,
            cwd=str(cwd),
            universal_newlines=True,
            stdout=stdout,
            stderr=stderr,
            env=env,
        )


class Verbosity(object):
    DEBUG = 2
    INFO = 1
    DEFAULT = 0
    QUIET = -1
    EXTRA_QUIET = -2


class Reporter(object):
    actionchar = "-"

    def __init__(self, session):
        self.tw = py.io.TerminalWriter()
        self.session = session
        self.reported_lines = []

    @property
    def verbosity(self):
        if self.session:
            return (
                self.session.config.option.verbose_level - self.session.config.option.quiet_level
            )
        else:
            return Verbosity.DEBUG

    def logpopen(self, popen, cmd_args_shell):
        """ log information about the action.popen() created process. """
        if popen.outpath:
            self.verbosity1("  {}$ {} >{}".format(popen.cwd, cmd_args_shell, popen.outpath))
        else:
            self.verbosity1("  {}$ {} ".format(popen.cwd, cmd_args_shell))

    def logaction_start(self, action):
        msg = "{} {}".format(action.msg, " ".join(map(str, action.args)))
        self.verbosity2("{} start: {}".format(action.venvname, msg), bold=True)
        assert not hasattr(action, "_starttime")
        action._starttime = time.time()

    def logaction_finish(self, action):
        duration = time.time() - action._starttime
        self.verbosity2(
            "{} finish: {} after {:.2f} seconds".format(action.venvname, action.msg, duration),
            bold=True,
        )
        delattr(action, "_starttime")

    def startsummary(self):
        if self.verbosity >= Verbosity.QUIET:
            self.tw.sep("_", "summary")

    def logline_if(self, level, msg, key=None, **kwargs):
        if self.verbosity >= level:
            message = str(msg) if key is None else "{}{}".format(key, msg)
            self.logline(message, **kwargs)

    def logline(self, msg, **opts):
        self.reported_lines.append(msg)
        self.tw.line("{}".format(msg), **opts)

    def keyboard_interrupt(self):
        self.error("KEYBOARDINTERRUPT")

    def keyvalue(self, name, value):
        if name.endswith(":"):
            name += " "
        self.tw.write(name, bold=True)
        self.tw.write(value)
        self.tw.line()

    def line(self, msg, **opts):
        self.logline(msg, **opts)

    def info(self, msg):
        self.logline_if(Verbosity.DEBUG, msg)

    def using(self, msg):
        self.logline_if(Verbosity.INFO, msg, "using ", bold=True)

    def good(self, msg):
        self.logline_if(Verbosity.QUIET, msg, green=True)

    def warning(self, msg):
        self.logline_if(Verbosity.QUIET, msg, "WARNING: ", red=True)

    def error(self, msg):
        self.logline_if(Verbosity.QUIET, msg, "ERROR: ", red=True)

    def skip(self, msg):
        self.logline_if(Verbosity.QUIET, msg, "SKIPPED: ", yellow=True)

    def verbosity0(self, msg, **opts):
        self.logline_if(Verbosity.DEFAULT, msg, **opts)

    def verbosity1(self, msg, **opts):
        self.logline_if(Verbosity.INFO, msg, **opts)

    def verbosity2(self, msg, **opts):
        self.logline_if(Verbosity.DEBUG, msg, **opts)


class Session:
    """The session object that ties together configuration, reporting, venv creation, testing."""

    def __init__(self, config, popen=subprocess.Popen, Report=Reporter):
        self.config = config
        self.popen = popen
        self.resultlog = ResultLog()
        self.report = Report(self)
        self.make_emptydir(config.logdir)
        config.logdir.ensure(dir=1)
        self.report.using("tox.ini: {}".format(self.config.toxinipath))
        self._spec2pkg = {}
        self._name2venv = {}
        try:
            self.venvlist = [self.getvenv(x) for x in self.evaluated_env_list()]
        except LookupError:
            raise SystemExit(1)
        except tox.exception.ConfigError as e:
            self.report.error(str(e))
            raise SystemExit(1)
        self._actions = []

    def evaluated_env_list(self):
        tox_env_filter = os.environ.get("TOX_SKIP_ENV")
        tox_env_filter_re = re.compile(tox_env_filter) if tox_env_filter is not None else None
        for name in self.config.envlist:
            if tox_env_filter_re is not None and tox_env_filter_re.match(name):
                msg = "skip environment {}, matches filter {!r}".format(
                    name, tox_env_filter_re.pattern
                )
                self.report.verbosity1(msg)
                continue
            yield name

    @property
    def hook(self):
        return self.config.pluginmanager.hook

    def _makevenv(self, name):
        envconfig = self.config.envconfigs.get(name, None)
        if envconfig is None:
            self.report.error("unknown environment {!r}".format(name))
            raise LookupError(name)
        elif envconfig.envdir == self.config.toxinidir:
            self.report.error(
                "venv {!r} in {} would delete project".format(name, envconfig.envdir)
            )
            raise tox.exception.ConfigError("envdir must not equal toxinidir")
        venv = VirtualEnv(envconfig=envconfig, session=self)
        self._name2venv[name] = venv
        return venv

    def getvenv(self, name):
        """ return a VirtualEnv controler object for the 'name' env.  """
        try:
            return self._name2venv[name]
        except KeyError:
            return self._makevenv(name)

    def newaction(self, venv, msg, *args):
        action = Action(self, venv, msg, args)
        self._actions.append(action)
        return action

    def runcommand(self):
        self.report.using("tox-{} from {}".format(tox.__version__, tox.__file__))
        verbosity = self.report.verbosity > Verbosity.DEFAULT
        if self.config.option.showconfig:
            self.showconfig()
        elif self.config.option.listenvs:
            self.showenvs(all_envs=False, description=verbosity)
        elif self.config.option.listenvs_all:
            self.showenvs(all_envs=True, description=verbosity)
        else:
            with self.cleanup():
                return self.subcommand_test()

    @contextmanager
    def cleanup(self):
        self.config.temp_dir.ensure(dir=True)
        try:
            yield
        finally:
            for tox_env in self.venvlist:
                if (
                    hasattr(tox_env, "package")
                    and isinstance(tox_env.package, py.path.local)
                    and tox_env.package.exists()
                ):
                    self.report.verbosity2("cleanup {}".format(tox_env.package))
                    tox_env.package.remove()
                    py.path.local(tox_env.package.dirname).remove(ignore_errors=True)

    def _copyfiles(self, srcdir, pathlist, destdir):
        for relpath in pathlist:
            src = srcdir.join(relpath)
            if not src.check():
                self.report.error("missing source file: {}".format(src))
                raise SystemExit(1)
            target = destdir.join(relpath)
            target.dirpath().ensure(dir=1)
            src.copy(target)

    def make_emptydir(self, path):
        if path.check():
            self.report.info("  removing {}".format(path))
            shutil.rmtree(str(path), ignore_errors=True)
            path.ensure(dir=1)

    def setupenv(self, venv):
        if venv.envconfig.missing_subs:
            venv.status = (
                "unresolvable substitution(s): {}. "
                "Environment variables are missing or defined recursively.".format(
                    ",".join(["'{}'".format(m) for m in venv.envconfig.missing_subs])
                )
            )
            return
        if not venv.matching_platform():
            venv.status = "platform mismatch"
            return  # we simply omit non-matching platforms
        with self.newaction(venv, "getenv", venv.envconfig.envdir) as action:
            venv.status = 0
            default_ret_code = 1
            envlog = self.resultlog.get_envlog(venv.name)
            try:
                status = venv.update(action=action)
            except IOError as e:
                if e.args[0] != 2:
                    raise
                status = (
                    "Error creating virtualenv. Note that spaces in paths are "
                    "not supported by virtualenv. Error details: {!r}".format(e)
                )
            except tox.exception.InvocationError as e:
                status = (
                    "Error creating virtualenv. Note that some special characters (e.g. ':' and "
                    "unicode symbols) in paths are not supported by virtualenv. Error details: "
                    "{!r}".format(e)
                )
            except tox.exception.InterpreterNotFound as e:
                status = e
                if self.config.option.skip_missing_interpreters == "true":
                    default_ret_code = 0
            if status:
                str_status = str(status)
                commandlog = envlog.get_commandlog("setup")
                commandlog.add_command(["setup virtualenv"], str_status, default_ret_code)
                venv.status = status
                if default_ret_code == 0:
                    self.report.skip(str_status)
                else:
                    self.report.error(str_status)
                return False
            commandpath = venv.getcommandpath("python")
            envlog.set_python_info(commandpath)
            return True

    def finishvenv(self, venv):
        with self.newaction(venv, "finishvenv"):
            venv.finish()
            return True

    def developpkg(self, venv, setupdir):
        with self.newaction(venv, "developpkg", setupdir) as action:
            try:
                venv.developpkg(setupdir, action)
                return True
            except tox.exception.InvocationError as exception:
                venv.status = exception
                return False

    def installpkg(self, venv, path):
        """Install package in the specified virtual environment.

        :param VenvConfig venv: Destination environment
        :param str path: Path to the distribution package.
        :return: True if package installed otherwise False.
        :rtype: bool
        """
        self.resultlog.set_header(installpkg=py.path.local(path))
        with self.newaction(venv, "installpkg", path) as action:
            try:
                venv.installpkg(path, action)
                return True
            except tox.exception.InvocationError as exception:
                venv.status = exception
                return False

    def subcommand_test(self):
        if self.config.skipsdist:
            self.report.info("skipping sdist step")
        else:
            for venv in self.venvlist:
                if not venv.envconfig.skip_install:
                    venv.package = self.hook.tox_package(session=self, venv=venv)
                    if not venv.package:
                        return 2
        if self.config.option.sdistonly:
            return
        for venv in self.venvlist:
            if self.setupenv(venv):
                if venv.envconfig.skip_install:
                    self.finishvenv(venv)
                else:
                    if venv.envconfig.usedevelop:
                        self.developpkg(venv, self.config.setupdir)
                    elif self.config.skipsdist:
                        self.finishvenv(venv)
                    else:
                        self.installpkg(venv, venv.package)

                self.runenvreport(venv)
                self.runtestenv(venv)
        retcode = self._summary()
        return retcode

    def runenvreport(self, venv):
        """
        Run an environment report to show which package
        versions are installed in the venv
        """
        with self.newaction(venv, "envreport") as action:
            packages = self.hook.tox_runenvreport(venv=venv, action=action)
        action.setactivity("installed", ",".join(packages))
        envlog = self.resultlog.get_envlog(venv.name)
        envlog.set_installed(packages)

    def runtestenv(self, venv, redirect=False):
        if self.config.option.notest:
            venv.status = "skipped tests"
        else:
            if venv.status:
                return
            self.hook.tox_runtest_pre(venv=venv)
            if venv.status == 0:
                self.hook.tox_runtest(venv=venv, redirect=redirect)
            self.hook.tox_runtest_post(venv=venv)

    def _summary(self):
        self.report.startsummary()
        retcode = 0
        for venv in self.venvlist:
            status = venv.status
            if isinstance(status, tox.exception.InterpreterNotFound):
                msg = " {}: {}".format(venv.envconfig.envname, str(status))
                if self.config.option.skip_missing_interpreters == "true":
                    self.report.skip(msg)
                else:
                    retcode = 1
                    self.report.error(msg)
            elif status == "platform mismatch":
                msg = " {}: {}".format(venv.envconfig.envname, str(status))
                self.report.skip(msg)
            elif status and status == "ignored failed command":
                msg = "  {}: {}".format(venv.envconfig.envname, str(status))
                self.report.good(msg)
            elif status and status != "skipped tests":
                msg = "  {}: {}".format(venv.envconfig.envname, str(status))
                self.report.error(msg)
                retcode = 1
            else:
                if not status:
                    status = "commands succeeded"
                self.report.good("  {}: {}".format(venv.envconfig.envname, status))
        if not retcode:
            self.report.good("  congratulations :)")

        path = self.config.option.resultjson
        if path:
            path = py.path.local(path)
            path.write(self.resultlog.dumps_json())
            self.report.line("wrote json report at: {}".format(path))
        return retcode

    def showconfig(self):
        self.info_versions()
        self.report.keyvalue("config-file:", self.config.option.configfile)
        self.report.keyvalue("toxinipath: ", self.config.toxinipath)
        self.report.keyvalue("toxinidir:  ", self.config.toxinidir)
        self.report.keyvalue("toxworkdir: ", self.config.toxworkdir)
        self.report.keyvalue("setupdir:   ", self.config.setupdir)
        self.report.keyvalue("distshare:  ", self.config.distshare)
        self.report.keyvalue("skipsdist:  ", self.config.skipsdist)
        self.report.tw.line()
        for envconfig in self.config.envconfigs.values():
            self.report.line("[testenv:{}]".format(envconfig.envname), bold=True)
            for attr in self.config._parser._testenv_attr:
                self.report.line("  {:<15} = {}".format(attr.name, getattr(envconfig, attr.name)))

    def showenvs(self, all_envs=False, description=False):
        env_conf = self.config.envconfigs  # this contains all environments
        default = self.config.envlist  # this only the defaults
        ignore = {self.config.isolated_build_env}.union(default)
        extra = [e for e in env_conf if e not in ignore] if all_envs else []

        if description:
            self.report.line("default environments:")
            max_length = max(len(env) for env in (default + extra))

        def report_env(e):
            if description:
                text = env_conf[e].description or "[no description]"
                msg = "{} -> {}".format(e.ljust(max_length), text).strip()
            else:
                msg = e
            self.report.line(msg)

        for e in default:
            report_env(e)
        if all_envs and extra:
            if description:
                self.report.line("")
                self.report.line("additional environments:")
            for e in extra:
                report_env(e)

    def info_versions(self):
        versions = ["tox-{}".format(tox.__version__)]
        proc = subprocess.Popen(
            (sys.executable, "-m", "virtualenv", "--version"), stdout=subprocess.PIPE
        )
        out, _ = proc.communicate()
        versions.append("virtualenv-{}".format(out.decode("UTF-8").strip()))
        self.report.keyvalue("tool-versions:", " ".join(versions))

    def _resolve_package(self, package_spec):
        try:
            return self._spec2pkg[package_spec]
        except KeyError:
            self._spec2pkg[package_spec] = x = self._get_latest_version_of_package(package_spec)
            return x

    def _get_latest_version_of_package(self, package_spec):
        if not os.path.isabs(str(package_spec)):
            return package_spec
        p = py.path.local(package_spec)
        if p.check():
            return p
        if not p.dirpath().check(dir=1):
            raise tox.exception.MissingDirectory(p.dirpath())
        self.report.info("determining {}".format(p))
        candidates = p.dirpath().listdir(p.basename)
        if len(candidates) == 0:
            raise tox.exception.MissingDependency(package_spec)
        if len(candidates) > 1:
            version_package = []
            for filename in candidates:
                version = get_version_from_filename(filename.basename)
                if version is not None:
                    version_package.append((version, filename))
                else:
                    self.report.warning("could not determine version of: {}".format(str(filename)))
            if not version_package:
                raise tox.exception.MissingDependency(package_spec)
            version_package.sort()
            _, package_with_largest_version = version_package[-1]
            return package_with_largest_version
        else:
            return candidates[0]


_REGEX_FILE_NAME_WITH_VERSION = re.compile(r"[\w_\-\+\.]+-(.*)\.(zip|tar\.gz)")


def get_version_from_filename(basename):
    m = _REGEX_FILE_NAME_WITH_VERSION.match(basename)
    if m is None:
        return None
    version = m.group(1)
    try:

        return pkg_resources.packaging.version.Version(version)
    except pkg_resources.packaging.version.InvalidVersion:
        return None
