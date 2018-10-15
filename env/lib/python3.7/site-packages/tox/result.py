import json
import socket
import subprocess
import sys

import tox


class ResultLog:
    def __init__(self, data=None):
        if not data:
            self.dict = {}
        elif isinstance(data, dict):
            self.dict = data
        else:
            self.dict = json.loads(data)
        self.dict.update({"reportversion": "1", "toxversion": tox.__version__})
        self.dict["platform"] = sys.platform
        self.dict["host"] = socket.getfqdn()

    def set_header(self, installpkg):
        """
        :param py.path.local installpkg: Path ot the package.
        """
        self.dict["installpkg"] = {
            "md5": installpkg.computehash("md5"),
            "sha256": installpkg.computehash("sha256"),
            "basename": installpkg.basename,
        }

    def get_envlog(self, name):
        testenvs = self.dict.setdefault("testenvs", {})
        d = testenvs.setdefault(name, {})
        return EnvLog(self, name, d)

    def dumps_json(self):
        return json.dumps(self.dict, indent=2)


class EnvLog:
    def __init__(self, reportlog, name, dict):
        self.reportlog = reportlog
        self.name = name
        self.dict = dict

    def set_python_info(self, python_executable):
        cmd = [
            str(python_executable),
            "-c",
            "import sys; import json;"
            "print(json.dumps({"
            "'executable': sys.executable,"
            "'version_info': list(sys.version_info),"
            "'version': sys.version}))",
        ]
        result = subprocess.check_output(cmd, universal_newlines=True)
        self.dict["python"] = json.loads(result)

    def get_commandlog(self, name):
        return CommandLog(self, self.dict.setdefault(name, []))

    def set_installed(self, packages):
        self.dict["installed_packages"] = packages


class CommandLog:
    def __init__(self, envlog, list):
        self.envlog = envlog
        self.list = list

    def add_command(self, argv, output, retcode):
        d = {}
        self.list.append(d)
        d["command"] = argv
        d["output"] = output
        d["retcode"] = str(retcode)
        return d
