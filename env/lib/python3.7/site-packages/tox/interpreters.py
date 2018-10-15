import distutils.util
import inspect
import re
import subprocess
import sys

import py

import tox


class Interpreters:
    def __init__(self, hook):
        self.name2executable = {}
        self.executable2info = {}
        self.hook = hook

    def get_executable(self, envconfig):
        """ return path object to the executable for the given
        name (e.g. python2.7, python3.6, python etc.)
        if name is already an existing path, return name.
        If an interpreter cannot be found, return None.
        """
        try:
            return self.name2executable[envconfig.envname]
        except KeyError:
            exe = self.hook.tox_get_python_executable(envconfig=envconfig)
            self.name2executable[envconfig.envname] = exe
            return exe

    def get_info(self, envconfig):
        executable = self.get_executable(envconfig)
        name = envconfig.basepython
        if not executable:
            return NoInterpreterInfo(name=name)
        try:
            return self.executable2info[executable]
        except KeyError:
            info = run_and_get_interpreter_info(name, executable)
            self.executable2info[executable] = info
            return info

    def get_sitepackagesdir(self, info, envdir):
        if not info.executable:
            return ""
        envdir = str(envdir)
        try:
            res = exec_on_interpreter(
                info.executable,
                [
                    inspect.getsource(sitepackagesdir),
                    "print(sitepackagesdir({!r}))".format(envdir),
                ],
            )
        except ExecFailed as e:
            print("execution failed: {} -- {}".format(e.out, e.err))
            return ""
        else:
            return res["dir"]


def run_and_get_interpreter_info(name, executable):
    assert executable
    try:
        result = exec_on_interpreter(executable, [inspect.getsource(pyinfo), "print(pyinfo())"])
    except ExecFailed as e:
        return NoInterpreterInfo(name, executable=e.executable, out=e.out, err=e.err)
    else:
        return InterpreterInfo(name, executable, **result)


def exec_on_interpreter(executable, source):
    if isinstance(source, list):
        source = "\n".join(source)
    from subprocess import Popen, PIPE

    args = [str(executable)]
    popen = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    popen.stdin.write(source.encode("utf8"))
    out, err = popen.communicate()
    if popen.returncode:
        raise ExecFailed(executable, source, out, err)
    try:
        result = eval(out.strip())
    except Exception:
        raise ExecFailed(executable, source, out, "could not decode {!r}".format(out))
    return result


class ExecFailed(Exception):
    def __init__(self, executable, source, out, err):
        self.executable = executable
        self.source = source
        self.out = out
        self.err = err


class InterpreterInfo:
    runnable = True

    def __init__(self, name, executable, version_info, sysplatform):
        assert executable and version_info
        self.name = name
        self.executable = executable
        self.version_info = version_info
        self.sysplatform = sysplatform

    def __str__(self):
        return "<executable at {}, version_info {}>".format(self.executable, self.version_info)


class NoInterpreterInfo:
    runnable = False

    def __init__(self, name, executable=None, out=None, err="not found"):
        self.name = name
        self.executable = executable
        self.version_info = None
        self.out = out
        self.err = err

    def __str__(self):
        if self.executable:
            return "<executable at {}, not runnable>".format(self.executable)
        else:
            return "<executable not found for: {}>".format(self.name)


if not tox.INFO.IS_WIN:

    @tox.hookimpl
    def tox_get_python_executable(envconfig):
        if envconfig.basepython == "python{}.{}".format(*sys.version_info[0:2]):
            return sys.executable
        return py.path.local.sysfind(envconfig.basepython)


else:

    @tox.hookimpl
    def tox_get_python_executable(envconfig):
        name = envconfig.basepython
        p = py.path.local.sysfind(name)
        if p:
            return p

        # Is this a standard PythonX.Y name?
        m = re.match(r"python(\d)(?:\.(\d))?", name)
        groups = [g for g in m.groups() if g] if m else []
        if m:
            # The standard names are in predictable places.
            actual = r"c:\python{}\python.exe".format("".join(groups))
        else:

            actual = win32map.get(name, None)
        if actual:
            actual = py.path.local(actual)
            if actual.check():
                return actual
        if name == "python{}.{}".format(*sys.version_info[0:2]):
            return sys.executable
        # Use py.exe to determine location - PEP-514 & PEP-397
        if m:
            return locate_via_py(*groups)

    # Exceptions to the usual windows mapping
    win32map = {"python": sys.executable, "jython": r"c:\jython2.5.1\jython.bat"}

    def locate_via_py(*parts):
        ver = "-{}".format(".".join(parts))
        script = "import sys; print(sys.executable)"
        py_exe = distutils.spawn.find_executable("py")
        if py_exe:
            proc = subprocess.Popen(
                (py_exe, ver, "-c", script), stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out, _ = proc.communicate()
            if not proc.returncode:
                return out.decode("UTF-8").strip()


def pyinfo():
    import sys

    return {"version_info": tuple(sys.version_info), "sysplatform": sys.platform}


def sitepackagesdir(envdir):
    import distutils.sysconfig

    return {"dir": distutils.sysconfig.get_python_lib(prefix=envdir)}
