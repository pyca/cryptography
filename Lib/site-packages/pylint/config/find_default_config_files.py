# Licensed under the GPL: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
# For details: https://github.com/PyCQA/pylint/blob/master/COPYING

import configparser
import os

import toml


def _toml_has_config(path):
    with open(path) as toml_handle:
        content = toml.load(toml_handle)
        try:
            content["tool"]["pylint"]
        except KeyError:
            return False

    return True


def _cfg_has_config(path):
    parser = configparser.ConfigParser()
    parser.read(path)
    return any(section.startswith("pylint.") for section in parser.sections())


def find_default_config_files():
    """Find all possible config files."""
    rc_names = ("pylintrc", ".pylintrc")
    config_names = rc_names + ("pyproject.toml", "setup.cfg")
    for config_name in config_names:
        if os.path.isfile(config_name):
            if config_name.endswith(".toml") and not _toml_has_config(config_name):
                continue
            if config_name.endswith(".cfg") and not _cfg_has_config(config_name):
                continue

            yield os.path.abspath(config_name)

    if os.path.isfile("__init__.py"):
        curdir = os.path.abspath(os.getcwd())
        while os.path.isfile(os.path.join(curdir, "__init__.py")):
            curdir = os.path.abspath(os.path.join(curdir, ".."))
            for rc_name in rc_names:
                rc_path = os.path.join(curdir, rc_name)
                if os.path.isfile(rc_path):
                    yield rc_path

    if "PYLINTRC" in os.environ and os.path.exists(os.environ["PYLINTRC"]):
        if os.path.isfile(os.environ["PYLINTRC"]):
            yield os.environ["PYLINTRC"]
    else:
        user_home = os.path.expanduser("~")
        if user_home not in ("~", "/root"):
            home_rc = os.path.join(user_home, ".pylintrc")
            if os.path.isfile(home_rc):
                yield home_rc
            home_rc = os.path.join(user_home, ".config", "pylintrc")
            if os.path.isfile(home_rc):
                yield home_rc

    if os.path.isfile("/etc/pylintrc"):
        yield "/etc/pylintrc"
